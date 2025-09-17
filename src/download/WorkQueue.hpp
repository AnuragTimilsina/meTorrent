#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>

class WorkQueue {
private:
    std::queue<int> pieces;
    mutable std::mutex mtx;
    std::condition_variable cv;
    bool finished = false;
    
public:
    void add_piece(int piece_index);
    bool get_piece(int& piece_index);
    void mark_finished();
    size_t size() const;
};