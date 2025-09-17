#include "WorkQueue.hpp"

void WorkQueue::add_piece(int piece_index) {
    std::lock_guard<std::mutex> lock(mtx);
    pieces.push(piece_index);
    cv.notify_one();
}

bool WorkQueue::get_piece(int& piece_index) {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [this] { return !pieces.empty() || finished; });
    
    if (pieces.empty()) {
        return false; // No more work
    }
    
    piece_index = pieces.front();
    pieces.pop();
    return true;
}

void WorkQueue::mark_finished() {
    std::lock_guard<std::mutex> lock(mtx);
    finished = true;
    cv.notify_all();
}

size_t WorkQueue::size() const {
    std::lock_guard<std::mutex> lock(mtx);
    return pieces.size();
}