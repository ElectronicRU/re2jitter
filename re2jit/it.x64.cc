extern "C" {
#include <sys/mman.h>
}
#include "re2/prog.h"
    #define private public
    #include "util/sparse_set.h"
    #undef private
#include "asm64.h"
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <algorithm>

#ifndef JIT_DEBUG
#define dprintf(...) {}
#else
#define dprintf(...) fprintf(stderr, ...)
#endif


namespace re2jit {

/* CLIST = current list pointer, NLIST = next list pointer
 * LISTSKIP = pointer to the end of current list
 * SEND, SCURRENT = string end and string current position
 * LISTBEGIN, LISTEND - denote the area within which the CLIST and NLIST reside,
 * RESULT is LISTEND and is memory address at which the result is
 * VIS is either the memory address of a bit array or, if bit array is less than 32 bits, the bit array register
 * GROUPSIZE is the size of RESULT array (and any state) in bytes
 * CHAR is the current character
 * FLAGS is matching flags, and VIS32 is convenience for 32-bit version of VIS */
static constexpr const as::r64 CLIST = as::rsi, NLIST = as::rdi, LISTSKIP = as::r14,
                 SEND = as::r8, SCURRENT = as::r9,
                 LISTBEGIN = as::r12, LISTEND = as::r13, VIS = as::r15,
                 GROUPSIZE = as::r10, RESULT = LISTEND,
                 SPARE = as::r11;
static constexpr const as::rb CHAR = as::dl;
static constexpr const as::r32 FLAGS = as::ebx, VIS32 = as::r32(VIS.id);
enum WORKFLAGS : as::i32 {
    MATCH_FOUND = 1 << 8,
    WAS_WORD = 1 << 9,
    NOT_FIRST = 1 << 10,
    BEGIN_TEXT = re2::kEmptyBeginText << 16,
    END_TEXT = re2::kEmptyEndText << 16,
    BEGIN_LINE = re2::kEmptyBeginLine << 16,
    END_LINE = re2::kEmptyEndLine << 16,
    WORD_BOUND = re2::kEmptyWordBoundary << 16,
    NON_BOUND = re2::kEmptyNonWordBoundary << 16,
};

struct native
{
    void * code_;
    size_t size_;
    re2::Prog *prog_;

    as::label REGEX_BEGIN;
    as::label REGEX_FINISH;

    // Emits CNEXT, a series of instruction that transistion to the next state.
    void emit_nextstate(as::code &code) {
        // wrap the list pointer around
        code.cmp(CLIST, LISTEND)
            .mov(LISTBEGIN, CLIST, as::equal)
            .lodsq()
            .jmp(as::rax);
    }

    // store the entry with the label on NLIST
    // This is more or less the opposite of CNEXT?..
    void store_state(as::code &code, as::label &lab) {
        code.cmp(NLIST, LISTEND)
            .mov(LISTBEGIN, NLIST, as::equal)
            .mov(lab, as::rax)
            .stosq();
    }

    void enqueue_for_state(as::code &, int, as::label&, bool init = false);

    void emit_empty_test(as::code &code) {
        as::label no_end_text, end_test, yes_word, no_word;
        code.cmp(SCURRENT, SEND).jmp(no_end_text, as::not_equal)
            .or_(END_TEXT | END_LINE, FLAGS).jmp(no_word);

        as::label no_end_line;
        code.mark(no_end_text)
            .mov(as::mem(SCURRENT), as::al)
            .cmp('\n', as::al).jmp(no_end_line, as::not_equal)
            .or_(END_LINE, FLAGS).mark(no_end_line);

        as::label l_wn, l_nw;
        code.cmp('_', as::al).jmp(yes_word, as::equal)
            .and_(as::i8(~32), as::al)
            .sub('A', as::al).cmp('Z' - 'A', as::al).jmp(no_word, as::more_u);
        // Here, the current character is a word
        code.mark(yes_word)
            .test(WAS_WORD, FLAGS).jmp(l_wn, as::zero)
            .or_(NON_BOUND, FLAGS).jmp(end_test)
            .mark(l_wn).or_(WORD_BOUND | WAS_WORD, FLAGS).jmp(end_test)
            .mark(no_word)
            .test(WAS_WORD, FLAGS).jmp(l_nw, as::not_zero)
            .or_(NON_BOUND, FLAGS).jmp(end_test)
            .mark(l_nw).or_(WORD_BOUND, FLAGS).and_(~WAS_WORD, FLAGS);

        code.mark(end_test);
    }

    void emit_bit_test(as::code &code, int id, as::label &skip_this) {
        if (state_info_[id].inpower & -2) {
            as::i32 div32, mod32;
            if (bit_memory_size_) {
                div32 = state_info_[id].bit_array_index / 32;
                mod32 = 1 << (state_info_[id].bit_array_index % 32);
                // test the relevant bit in the VIS
                code.test(mod32, as::mem(VIS + div32 * 4))
                    .jmp(skip_this, as::not_zero)
                    .or_(mod32, as::mem(VIS + div32 * 4));
            } else {
                as::i32 mask;
                mask = 1 << state_info_[id].bit_array_index;
                code.test(mask, VIS32)
                    .jmp(skip_this, as::not_zero)
                    .or_(mask, VIS32);
            }
        }
    }

    // Emits CLAST, a special code place that terminates the state list.
    // We in total need 3 different versions: the one that does add states, and the one that doesn't
    // (labeled kind = 0, 1)
    // the general case is not in the beginning of the string, because we handle that separately
    void emit_laststate(as::code &code,
            int state0,
            as::label &start_match) {
        as::label clast, cend, do_add;
        code.mark(clast)
        // if we have a match, no point searching for a new one
            .test(NOT_FIRST, FLAGS).jmp(do_add, as::zero)
            .test(RE2JIT_ANCHOR_START, FLAGS).jmp(cend, as::not_zero)
            .test(MATCH_FOUND, FLAGS).jmp(cend, as::not_zero)
            .mark(do_add).or_(NOT_FIRST, FLAGS);
        code.xchg(CLIST, NLIST)
            .mov(SCURRENT, as::rax).stosq()
            .mov(0, as::eax).mov(GROUPSIZE, as::rcx).shr(3, as::rcx).dec(as::rcx)
            .repz().stosq()
            .sub(GROUPSIZE, NLIST)
            .xchg(CLIST, NLIST);
        dprintf("INITIAL\n");
        enqueue_for_state(code, state0, cend, true);

        code.cmp(SEND, SCURRENT).jmp(REGEX_FINISH, as::equal)  // if the end of the string, end it
            .mov(CLIST + GROUPSIZE, as::rax).cmp(as::rax, NLIST).jmp(REGEX_FINISH, as::equal)  // if the list is empty, move out
            .mov(as::mem(SCURRENT), CHAR)
            .inc(SCURRENT)
            .and_(as::i32(0xffff), FLAGS);
        {
            as::label L;
            code.cmp('\n', CHAR).jmp(L, as::not_equal).or_(BEGIN_LINE, FLAGS).mark(L);
        }
        code.mark(start_match);
        emit_empty_test(code);
        code.mov(NLIST, LISTSKIP);
        if (bit_memory_size_) {
            // clear visited
            code.mov(VIS, NLIST)
                .mov(0, as::eax)
                .mov(bit_memory_size_, as::ecx)
                .repz().stosl()
                .mov(LISTSKIP, NLIST);
        } else {
            code.xor_(VIS32, VIS32);
        }
        store_state(code, clast);  // add ourselves to the end of the next list
        code.add(GROUPSIZE, NLIST);
        // get next character
        emit_nextstate(code);
    }

    struct StackedState {
        as::label label;
        int id;
        int saved_size;
        as::i32 saved_index;
        StackedState() {}
        StackedState(int id, as::i32 saved, int size) : label(), id(id), saved_size(size), saved_index(saved) {}
    };

    struct StackedState *state_stack_;
    re2::SparseSet state_set_;
    as::label *state_labels_;

    void encode_state(as::code &code, int state_id) {
        re2::Prog::Inst *ip = prog_->inst(state_id);
        as::label cnext, dont_skip;
        switch (ip->opcode()) {
        default:
            return;

        case re2::kInstByteRange:
            dprintf("byte range %d[%d %d] %d\n", state_id, ip->lo(), ip->hi(), (int)ip->foldcase());
            code.mark(state_labels_[state_id]);
            if (ip->lo() == ip->hi()) {
                if (ip->foldcase()) {
                    if ('a' <= ip->lo() && ip->lo() <= 'z') {
                        code.cmp(ip->lo() - 'a' + 'A', CHAR)
                            .jmp(dont_skip, as::equal);
                    }
                }
                code.cmp(ip->lo(), CHAR)
                    .jmp(cnext, as::not_equal)
                    .mark(dont_skip);
            } else if (ip->lo() == 0x00 and ip->hi() == 0xff) {
                // accept
            } else if (ip->foldcase() && 'a' <= ip->lo() && ip->hi() <= 'z') {
                code.mov(CHAR, as::al)
                    .or_(as::i8(32), as::al)
                    .sub(ip->lo(), as::al)
                    .cmp(ip->hi() - ip->lo(), as::al)
                    .jmp(cnext, as::more_u);
            } else {
                if (ip->foldcase()) {
                    int lo = std::max(ip->lo(), (int)'a') - 'a' + 'A',
                        hi = std::min(ip->hi(), (int)'z') - 'z' + 'Z';
                    if (lo == hi) {
                        code.cmp(lo, CHAR).jmp(dont_skip, as::equal);
                    } else if (lo < hi) {
                        code.mov(CHAR, as::al)
                            .sub(lo, as::al)
                            .cmp(hi - lo, as::al)
                            .jmp(dont_skip, as::less_equal_u);
                    }
                }
                code.mov(CHAR, as::al)
                    .sub(ip->lo(), as::al)
                    .cmp(ip->hi() - ip->lo(), as::al)
                    .jmp(cnext, as::more_u)
                    .mark(dont_skip);
            }
            enqueue_for_state(code, ip->out(), cnext);
            emit_nextstate(code);
            break;
        }
    }

    struct StateInfo {
        int inpower;
        int bit_array_index;
    };

    struct StateInfo *state_info_;

    int bit_array_size_;
    int number_of_states_;
    int bit_memory_size_;

    void init_state_info() {
        state_info_ = new StateInfo[prog_->size()];
        memset(state_info_, 0, prog_->size() * sizeof(StateInfo));

        std::deque<int> state_deque = { prog_->start() };

        while (!state_deque.empty()) {
            int id = state_deque.front();
            state_deque.pop_front();
            int nstk = 0;
            state_stack_[nstk++].id = id;
            state_set_.clear();
            while (nstk > 0) {
                StackedState &ss = state_stack_[--nstk];
                if (state_set_.contains(ss.id))
                    continue;
                state_set_.insert_new(ss.id);
                re2::Prog::Inst *ip = prog_->inst(ss.id);
                switch (ip->opcode()) {
                    default:
                        throw std::runtime_error("cannot handle that yet");

                    case re2::kInstEmptyWidth:
                    case re2::kInstNop:
                    case re2::kInstCapture:
                        state_stack_[nstk++].id = ip->out();
                        break;

                    case re2::kInstMatch:
                        state_info_[ss.id].inpower--;

                    case re2::kInstFail:
                        break;


                    case re2::kInstAltMatch:  // treat them the same for now
                    case re2::kInstAlt:
                        state_stack_[nstk++].id = ip->out1();
                        state_stack_[nstk++].id = ip->out();
                        break;

                    case re2::kInstByteRange:
                        if (!(state_info_[ss.id].inpower++)) {
                            state_deque.push_back(ip->out());
                        }
                        break;
                }
            }
        }

        number_of_states_ = 0;
        bit_array_size_ = 0;
        for (int i = 0; i < prog_->size(); ++i) {
            if (state_info_[i].inpower > 0) {
                ++number_of_states_;
            }
            if (state_info_[i].inpower & -2) { //not 0 or 1
                state_info_[i].bit_array_index = bit_array_size_++;
            }
        }
        if (bit_array_size_ > 32)
            bit_memory_size_ = (bit_array_size_ + 31) / 32;
        else
            bit_memory_size_ = 0;
    }




    native(re2::Prog *prog) : code_(NULL), size_(0), prog_(prog)
    {
        state_stack_ = new StackedState[prog_->size() * 2]; // at most one main stack state and one helper one
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
            .push(as::rbx)
            .push(as::r12)
            .push(as::r13)
            .push(as::r14)
            .push(as::r15);

        code.mov(as::rcx, LISTBEGIN)
            .mov(as::r8, LISTEND)
            .mov(as::r9, GROUPSIZE);

        if (bit_memory_size_)
            code.mov(LISTEND + GROUPSIZE, VIS);

        code.mov(as::rdi, SCURRENT)
            .mov(as::rsi, SEND)

            .mov(as::rcx, CLIST)
            .mov(as::rcx, NLIST)

            .mov(as::edx, FLAGS);


        as::label start_match;
        code.or_(BEGIN_TEXT | BEGIN_LINE, FLAGS);
        code.jmp(start_match);
        emit_laststate(code, prog_->start(), start_match);

        for (int i = 0; i < prog->size(); ++i) {
            if (state_info_[i].inpower > 0) {
                encode_state(code, i);
            }
        }
        
        code.mark(REGEX_FINISH)
            .mov(FLAGS, as::eax)
            .and_(MATCH_FOUND, as::eax)
            .pop(as::r15)
            .pop(as::r14)
            .pop(as::r13)
            .pop(as::r12)
            .pop(as::rbx)
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
        typedef int f(const char*, const char*, int, void *, void *, long);
        int groupsize = (ngroups ?: 1) * 2 * 8;
        int listsize = (number_of_states_ + 1) * 2 * (8 + groupsize);
        int memsize = listsize + groupsize + bit_memory_size_ * 4;
        char *list_groups_visited = (char *)malloc(memsize);
        memset(list_groups_visited, 0, memsize);
        if (flags & RE2JIT_ANCHOR_END)
            flags |= RE2JIT_MATCH_RIGHTMOST;
        int result = ((f *) code_)(text.begin(), text.end(), flags, list_groups_visited, list_groups_visited + listsize, groupsize);
        if (result) {
            if (ngroups) {
                char **pgroups = (char **)(list_groups_visited + listsize);
                for (int i = 0; i < ngroups; ++i) {
                    groups[i].set(pgroups[2 * i], pgroups[2 * i + 1] - pgroups[2 * i]);
                }
            }
        }
        free(list_groups_visited);
        return result;
    }
};


// When entering this block of code, RSI points to the location of group capture state
// (the area immediately following the state address in CLIST),
// RDI points to the NLIST.
// Afterwards, RSI is wound forward by GROUPSIZE, and RDI is rewound by whatever number of states
// got encoded.
// If a match got encountered, RSI might be rewound to LISTEND.
// if `init' is true, then RSI is never rewound to LISTEND (although still wound forward),
// and captures never store anything on stack (the current capture is assumed to be all zeros).
void native::enqueue_for_state(as::code &code, int statenum, as::label &cnext, bool init) {
    code.push(as::rbp).mov(as::rsp, as::rbp);
    int nstk = 0;
    state_stack_[nstk++].id = statenum;
    state_set_.clear();
    as::label end_of_the_line;
    while (nstk > 0) {
        StackedState &ss = state_stack_[--nstk];
        if (ss.id == 0 && ss.saved_index) {
            dprintf("\t <- end capture %x\n", (int)ss.saved_index);
            // it's a phony that tells us to restore
            as::label skip_cap;
            code.cmp(ss.saved_index, GROUPSIZE)
                .jmp(skip_cap, as::less_equal_u);
            if (init) {
                code.mov(0, as::mem(CLIST + ss.saved_index));
            } else {
                code.pop(as::mem(CLIST + ss.saved_index));
            }
            code.mark(skip_cap);
            continue;
        } else if (ss.id == 0 && ss.saved_index == 0) {
            dprintf("\t <- end empty\n");
            code.mark(ss.label);
            // reset state set to before the empty width
            state_set_.size_ = ss.saved_size;
            continue;
        }
        if (state_set_.contains(ss.id))
            continue;
        state_set_.insert_new(ss.id);
        re2::Prog::Inst *ip = prog_->inst(ss.id);
        as::label skip_this, skip_cap;
        as::i32 cap;
        switch (ip->opcode()) {
        default:
            throw std::runtime_error("cannot handle that yet");

        case re2::kInstEmptyWidth:
            dprintf("\t -> empty %d %#x {\n", ss.id, ip->empty());
            state_stack_[nstk] = StackedState(0, 0, state_set_.size());
            code.mov(FLAGS, as::eax).not_(as::eax)
                .test(as::i32(ip->empty()) << 16, as::eax)
                .jmp(state_stack_[nstk++].label, as::not_zero);
            state_stack_[nstk++].id = ip->out();
            break;


        case re2::kInstFail:
            break;

        case re2::kInstMatch:
            dprintf("\t -> %d (match)\n", ss.id);
            emit_bit_test(code, ss.id, skip_this);
            // if required to be at end and not at end, skip this
            {
                as::label L;
                code.test(RE2JIT_ANCHOR_END, FLAGS).jmp(L, as::zero)
                    .cmp(SCURRENT, SEND).jmp(skip_this, as::not_equal)
                    .mark(L);
            }
            // if longest-mode, check if the new match is longer
            {
                as::label leftmost_best;
                code.test(RE2JIT_MATCH_RIGHTMOST, FLAGS).jmp(leftmost_best, as::zero);
                as::label or_true, and_false;
                code.test(MATCH_FOUND, FLAGS).jmp(or_true, as::zero) // if match not found yet or
                    .mov(as::mem(CLIST), as::rax).cmp(as::rax, as::mem(RESULT))
                    .jmp(or_true, as::more_u) // capture[0] < match[0]
                    .jmp(and_false, as::not_equal) // or (capture[0] == match[0] &&
                    .mov(as::mem(CLIST + 8), as::rax).cmp(as::rax, as::mem(RESULT + 8))
                    .jmp(or_true, as::less_u) // && capture[1] > match[1]
                    .mark(and_false).jmp(skip_this)
                    .mark(or_true).mark(leftmost_best);
            }
            // Here, the match is better either by definition, or because it is leftmost-longer
            code.mov(SCURRENT, as::mem(CLIST + 8))
                .or_(MATCH_FOUND, FLAGS)
                // we gonna write to RESULT, so use it to store current RDI value for us..
                .mov(NLIST, SPARE).mov(RESULT, NLIST)
                .mov(GROUPSIZE, as::rcx)
                .shr(3, as::rcx)
                .repz().movsq()
                .sub(GROUPSIZE, CLIST)
                .mov(SPARE, NLIST);

            // if it is NOT the longest match, terminate all current threads
            // and don't add any future ones
            code.test(RE2JIT_MATCH_RIGHTMOST, FLAGS).jmp(skip_this, as::not_zero);
            // pop the balloon!
            code.mov(as::rbp, as::rsp).pop(as::rbp);
            if (!init)
                code.mov(LISTSKIP, CLIST).jmp(end_of_the_line);
            else
                code.jmp(cnext);
            code.mark(skip_this);
            break;

        case re2::kInstAltMatch:  // treat them the same for now
        case re2::kInstAlt:
            state_stack_[nstk++].id = ip->out1();
            state_stack_[nstk++].id = ip->out();
            break;

        case re2::kInstCapture:
            cap = ip->cap() * 8;
            dprintf("\t -> capture %d %x\n", ss.id, (int)cap);
            // check if we actually want to capture it
            code.cmp(cap, GROUPSIZE)
                .jmp(skip_cap, as::less_equal_u);
            if (nstk > 0) {
                // we have to clean up for the future
                state_stack_[nstk++] = StackedState(0, cap, 0);
                if (!init)
                    code.push(as::mem(CLIST + cap));
            }
            code.mov(SCURRENT, as::mem(CLIST + cap))
                .mark(skip_cap);
            state_stack_[nstk++].id = ip->out();
            break;

        case re2::kInstNop:
            state_stack_[nstk++].id = ip->out();
            break;

        case re2::kInstByteRange:
            dprintf("\t -> %d (byte range)\n", ss.id);
            // state worth recording
            if (state_info_[ss.id].inpower == 0) {
                fprintf(stderr, "state %d (inpower %d) reaching state %d\n", statenum, state_info_[statenum].inpower, ss.id);
                throw std::runtime_error("state somehow not detected during walk");
            }
            emit_bit_test(code, ss.id, skip_this);
            store_state(code, state_labels_[ss.id]);
            // copy the capture state
            code.mov(GROUPSIZE, as::rcx)
                .shr(3, as::rcx)
                .repz().movsq()
                .sub(GROUPSIZE, CLIST);
            code.mark(skip_this);
            break;
        }
    }
    code.pop(as::rbp)
        .mark(cnext)
        .add(GROUPSIZE, CLIST)
        .mark(end_of_the_line);
}

};
