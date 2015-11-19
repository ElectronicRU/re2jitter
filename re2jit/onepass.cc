// We don't need to be as greedy as re2/onepass.cc (only working on short stuff with max 4 capture groups, etc.)
// since our data structures are temporary and are only used to generate code.
// We want to try REALLY hard to make as much of the regexp one-pass as possible.

#include "util/util.h"
#include "re2/prog.h"

namespace re2jit {

    struct Action {
        // we might be at the end of a closing loop, so let's not save up on indices...
        uint32 next_index;
        // flags are the lower bits (empty flags), captures are the upper bit.
        // Capture numbers are relative to the node's min_capture, so it can 
        // encompass ~26 closely-situated captures. Because of how regexps
        // are written, this is most certainly good enough.
        uint32 flags_and_captures;
        // Overall, this is twice the memory re2/onepass.cc uses. It's okay though,
        // it's only a temporary representation.
    };

    struct OnePassNode {
        uint32 base_capture_index;
        Action *actions;
    };

}

