#ifndef FDT_H
#define FDT_H

#include <fstream>
#include <string>
#include <vector>

namespace ns3 {
    enum fdt_stat : uint8_t {
        file = 0,
        close
    };

    struct FileDescriptor {
        fdt_stat stat;
        std::string filename;
        std::string checksum;
        uint8_t chunck_id;
        uint8_t chunck_num;
        uint64_t start_from;
        size_t byte;
        size_t acknowledged;
    };
} // namespace ns3

#endif
