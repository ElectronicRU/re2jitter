extern "C" {
#include <sys/mman.h>
}
#include "re2/prog.h"
#include "util/sparse_set.h"
#include "asm64.h"
#include <cstdio>
#include <cstdlib>

#define printf(...) {}
#define putchar(...) {}

namespace re2jit {
static constexpr const as::r64 CLIST = as::rsi, NLIST = as::rdi, LISTSKIP = as::r14,
                 SEND = as::r8, SCURRENT = as::r9, SMATCH = as::r10,
                 LISTBEGIN = as::r12, LISTEND = as::r13, VIS = as::r11;
static constexpr const as::rb CHAR = as::dl;
static constexpr const as::r32 FLAGS = as::ebx, VIS32 = as::r32(VIS.id);

struct native
{
    void * code_;
    size_t size_;
    re2::Prog *prog_;

    as::label REGEX_BEGIN;
    as::label REGEX_FINISH;

    // Emits CNEXT, a series of instruction that transistion to the next state.
    void emit_nextstate(as::code &code) {
        code.lodsq()
            // wrap the list pointer around
            .cmp(CLIST, LISTEND)
            .mov(LISTBEGIN, CLIST, as::equal)
            .jmp(as::rax);
    }

    // store the entry with the label on NLIST
    // This is more or less the opposite of CNEXT?..
    void store_state(as::code &code, as::label &lab) {
        code.mov(lab, as::rax)
            .stosq()
            .cmp(NLIST, LISTEND)
            .mov(LISTBEGIN, NLIST, as::equal);
    }

    void enqueue_for_state(as::code &, int, bool threadkill = true);

    // Emits CLAST, a special code place that terminates the state list.
    // We in total need 3 different versions: the one that does add states, and the one that doesn't
    // (labeled kind = 0, 1)
    // the general case is not in the beginning of the string, because we handle that separately
    void emit_laststate(as::code &code,
            int state0,
            as::label &start_match) {
        as::label clast, cend;
        code.mark(clast);
        // if we have a match, no point searching for a new one
        code.test(RE2JIT_ANCHOR_START, FLAGS).jmp(cend, as::not_zero);
        code.test(SMATCH, SMATCH).jmp(cend, as::not_zero);
        code.mark(start_match);
        enqueue_for_state(code, state0, false);
        // now that we've found all possible and impossible matches, we can bail out
        code.mark(cend)
            .cmp(SEND, SCURRENT).jmp(REGEX_FINISH, as::equal)  // if the end of the string, end it
            // if the list is empty, move out
            .cmp(CLIST, NLIST).jmp(REGEX_FINISH, as::equal)
            .mov(NLIST, LISTSKIP);
        if (bit_memory_size_) {
            // clear visited
            code.mov(VIS, as::rdi)
                .mov(0, as::al)
                .mov((bit_array_size_ + 7) / 8, as::ecx)
                .repz().stosb()
                .mov(LISTSKIP, as::rdi);  // yes we are hypocrites, this code knows that NLIST is rdi
        } else {
            code.xor_(VIS32, VIS32);
        }
        store_state(code, clast); // add ourselves to the end of the next list
        // get next character
        code.mov(as::mem(SCURRENT), CHAR)
            .inc(SCURRENT);
        emit_nextstate(code);
    }

    struct StackedState {
        int id;
    };

    struct StackedState *state_stack_;
    re2::SparseSet state_set_;
    as::label *state_labels_;

    void encode_state(as::code &code, int state_id) {
        re2::Prog::Inst *ip = prog_->inst(state_id);
        as::label cnext;
        switch (ip->opcode()) {
        default:
            putchar('\n');
            return;

        case re2::kInstByteRange:
            printf("byte range %d[%d %d] %d\n", state_id, ip->lo(), ip->hi(), (int)ip->foldcase());
            code.mark(state_labels_[state_id]);
            if (ip->lo() == ip->hi()) {
                code.cmp(ip->lo(), CHAR)
                    .jmp(cnext, as::not_equal);
            } else if (ip->lo() == 0x00 and ip->hi() == 0xff) {
                // accept
            } else {
                code.mov(CHAR, as::al)
                    .sub(ip->lo(), as::al)
                    .cmp(ip->hi() - ip->lo(), as::al)
                    .jmp(cnext, as::more_u);
            }
            enqueue_for_state(code, ip->out());
            code.mark(cnext);
            emit_nextstate(code);
            break;
        }
    }

    struct StateInfo {
        int inpower;
        int bit_array_index;
    };

    struct StateInfo *state_info_;

    void state_info_dfs(int statenum) {
        if (state_info_[statenum].inpower++)
            return;
        re2::Prog::Inst *ip = prog_->inst(statenum);
        switch (ip->opcode()) {
            case re2::kInstMatch:
            case re2::kInstFail:
                break;

            case re2::kInstAlt:
            case re2::kInstAltMatch:
                state_info_dfs(ip->out());
                state_info_dfs(ip->out1());
                break;

            default:
                state_info_dfs(ip->out());
        }
    }

    int bit_array_size_;
    int number_of_states_;
    int bit_memory_size_;

    void init_state_info() {
        state_info_ = new StateInfo[prog_->size()];
        memset(state_info_, 0, prog_->size() * sizeof(StateInfo));
        state_info_dfs(prog_->start());
        number_of_states_ = 0;
        bit_array_size_ = 0;
        for (int i = 0; i < prog_->size(); ++i) {
            if (state_info_[i].inpower > 0) {
                ++number_of_states_;
                if (state_info_[i].inpower > 1) {
                    state_info_[i].bit_array_index = bit_array_size_++;
                }
            }
        }
        if (bit_array_size_ > 32)
            bit_memory_size_ = (bit_array_size_ + 7) / 8;
        else
            bit_memory_size_ = 0;
    }




    native(re2::Prog *prog) : code_(NULL), size_(0), prog_(prog)
    {
        state_stack_ = new StackedState[prog_->size()];
        state_set_.resize(prog_->size());
        state_labels_ = new as::label[prog_->size()]();

        init_state_info();

        as::code code;

        // System V ABI:
        //   * первые 6 аргументов - rdi, rsi, rdx, rcx, r8, r9
        //   * остальные на стеке
        //   * возвращаемое значение - rax
        //   * регистры rax, rcx, rdx, rdi, rsi, r8, r9, r10 при вызовах не сохраняются
        //   * регистры rbx, rsp, rbp, r11-r15 -- сохраняются.
        //     сгенерированного кода это тоже касается. если испортить значение
        //     в регистре, поведение после ret будет непредсказуемым.

        // Prologue. It's just handcrafted mostly.
        code.mark(REGEX_BEGIN)
            .push(as::rbp)
            .mov(as::rsp, as::rbp)
            .push(as::r64(CHAR.id))
            .push(LISTBEGIN)
            .push(LISTEND)
            .push(LISTSKIP)
            .push(VIS);

        code.mov(as::rcx, LISTBEGIN)
            .mov(as::ptr(as::rcx + 2 * 8 * (number_of_states_+ 1)), LISTEND);

        if (bit_memory_size_)
            code.mov(LISTEND, VIS);
        else
            code.xor_(VIS32, VIS32);

        code.mov(as::rdi, SCURRENT)
            .mov(as::rsi, SEND)
            .xor_(SMATCH, SMATCH)

            .mov(as::rcx, CLIST)
            .mov(as::rcx, NLIST)

            .mov(as::edx, FLAGS);


        // this code could theoretically be more optimized by nearly doubling its size,
        // but currently I find it hard to give half a shit about it.
        as::label start_match;
        code.jmp(start_match);
        emit_laststate(code, prog_->start(), start_match);

        for (int i = 0; i < prog->size(); ++i) {
            if (state_info_[i].inpower > 0) {
                encode_state(code, i);
            }
        }

        as::label move_out;
        code.mark(REGEX_FINISH)
            .test(RE2JIT_ANCHOR_END, FLAGS)
            .jmp(move_out, as::zero)
            .cmp(SEND, SMATCH)
            .jmp(move_out, as::equal)
            .xor_(SMATCH, SMATCH)
            .mark(move_out);

        code.mov(SMATCH, as::rax)
            .pop(VIS)
            .pop(LISTSKIP)
            .pop(LISTEND)
            .pop(LISTBEGIN)
            .pop(as::r64(CHAR.id))
            .pop(as::rbp)
            .ret();


        size_t sz = code.size();
        void * tg = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (tg == (void *) -1)
            throw std::runtime_error("mmap failed");

        if (!code.write(tg)) {
            munmap(tg, sz);
            throw std::runtime_error("a label was used but not set");
        }

        FILE *f = fopen("asd.bin", "wb");
        fwrite(tg, 1, sz, f);
        fclose(f);

        if (mprotect(tg, sz, PROT_READ | PROT_EXEC) == -1) {
            munmap(tg, sz);
            throw std::runtime_error("can't change permissions");
        }

        code_ = tg;
        size_ = sz;
    }

    ~native()
    {
        munmap(code_, size_);
        delete[] state_stack_;
        delete[] state_labels_;
        delete[] state_info_;
    }

    bool match(const re2::StringPiece &text, int flags,
            re2::StringPiece *groups, int ngroups)
    {
        typedef char *f(const char*, const char*, int, void *);
        int listsize = (number_of_states_ + 1) * 2 * 8;
        int memsize = listsize + bit_memory_size_;
        char *list_visited = (char *)malloc(memsize);
        if (bit_memory_size_) {
            memset(list_visited + listsize, 0, bit_memory_size_);
        }
        if (flags & RE2JIT_ANCHOR_END)
            flags |= RE2JIT_MATCH_RIGHTMOST;
        char *result = ((f *) code_)(text.data(), text.data() + text.size(), flags, list_visited);
        free(list_visited);
        if (result) {
            if (ngroups)
                groups[0].set(text.data(), result - text.data());
            return 1;
        }
        return 0;
    }
};
void native::enqueue_for_state(as::code &code, int statenum, bool threadkill) {
    int nstk = 0;
    state_stack_[nstk++].id = statenum;
    state_set_.clear();
    as::label end_of_the_line;
    while (nstk > 0) {
        const StackedState &ss = state_stack_[--nstk];
        if (state_set_.contains(ss.id))
            continue;
        state_set_.insert_new(ss.id);
        re2::Prog::Inst *ip = prog_->inst(ss.id);
        as::label skip_this;
        as::s32 div8;
        as::i8 mod8;
        as::i32 mask;
        switch (ip->opcode()) {
        default:
            throw std::runtime_error("cannot handle that yet");

        case re2::kInstFail:
            break;

        case re2::kInstMatch:
            printf("\t-> %d (match)\n", ss.id);
            // Any match we found can be considered always better.
            code.mov(SCURRENT, SMATCH)
                // if it is NOT the longest match, terminate all current threads
                // and don't add any future ones
                .test(RE2JIT_MATCH_RIGHTMOST, FLAGS);
            if (threadkill)
                code.mov(LISTSKIP, CLIST, as::zero);
            code.jmp(end_of_the_line, as::zero);
            break;

        case re2::kInstAltMatch:  // treat them the same for now
        case re2::kInstAlt:
            state_stack_[nstk++].id = ip->out1();
            state_stack_[nstk++].id = ip->out();
            break;

        case re2::kInstCapture:
            // ignore, lol
        case re2::kInstNop:
            state_stack_[nstk++].id = ip->out();
            break;

        case re2::kInstByteRange:
            printf("\t -> %d (byte range)\n", ss.id);
            // state worth recording
            if (state_info_[ss.id].inpower > 1) {
                if (bit_memory_size_) {
                    div8 = state_info_[ss.id].bit_array_index / 8;
                    mod8 = 1 << (state_info_[ss.id].bit_array_index % 8);
                    // test the relevant bit in the VIS
                    code.test(mod8, as::mem(VIS + div8))
                        .jmp(skip_this, as::not_zero)
                        .or_(mod8, as::mem(VIS + div8));
                } else {
                    mask = 1 << state_info_[ss.id].bit_array_index;
                    code.test(mask, VIS32)
                        .jmp(skip_this, as::not_zero)
                        .or_(mask, VIS32);
                }
            }
            store_state(code, state_labels_[ss.id]);
            code.mark(skip_this);
            break;
        }
    }
    code.mark(end_of_the_line);
}

};
