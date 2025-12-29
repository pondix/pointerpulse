#include "replicapulse/gtid_set.h"

#include <cassert>
#include <string>

using namespace replicapulse;

int main() {
    GtidSet set;
    set.merge_set("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1-3:10-12");
    set.add_gtid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:4"); // merges to 1-4
    set.add_gtid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:9"); // joins with 10-12
    set.add_gtid("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:7");

    std::string out = set.to_string();
    assert(out.find("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1-4:9-12") != std::string::npos);
    assert(out.find("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:7-7") != std::string::npos);
    return 0;
}

