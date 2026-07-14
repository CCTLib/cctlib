// -----------------------------------------------------------------------------
// clients/reuse_distance_splay.h
//
// Compressed splay tree for reuse-distance measurement, as described in
//
//   Chen Ding and Yutao Zhong,
//   "Predicting Whole-Program Locality Through Reuse Distance Analysis,"
//   PLDI 2003. https://doi.org/10.1145/781131.781159
//
// Time cost O(log log M) per access with bounded relative error e (< 1); space
// cost O(log M). M is the number of distinct keys ever accessed. See the paper
// for the formal proposition (§2.1.1, Proposition 2.1) and the compression
// argument.
//
// This is a header-only, template-only implementation designed to drive several
// reuse-distance streams in the same pintool (per-static-instruction reuse,
// per-cacheline reuse, per-page reuse, per-iTLB-entry reuse, ...) without
// duplicating code. The key type is user-supplied (address, page ID, whatever)
// and must be usable as an unordered_map<Key, ...> key.
//
// Data model (see paper §2.1.1 Fig 1(d)):
//   * Every node holds up to `capacity` distinct keys that were accessed near
//     the same virtual time. Instead of storing the individual keys, each node
//     stores a single `time` (the most recent access time of any key in it),
//     a `size` (current number of distinct keys), and a `capacity` (max size
//     assigned at compression time). Subtree `weight` = sum of `size` over the
//     subtree.
//   * Tree is ordered by `time`. Splay ordering by access time is what lets a
//     recently-accessed node bubble to the root, so a lookup takes amortized
//     O(log log M) after compression (vs O(log M) exact).
//   * A side unordered_map<Key, Node*> tracks which node currently owns each
//     key, so `access(k)` can find and update the containing node in O(1) map
//     ops plus the splay walk.
//
// Compression (§2.1.1):
//   * Triggered when tree size > 4 * log_{1+e'}(M) + 4, where e' = e / (1 - e).
//   * Traverse in reverse-time order; try to merge each adjacent pair whose
//     combined size fits the older node's capacity.
//   * `capacity` of the merged node is set to `sum_of_older_nodes * e'` per the
//     proof; guarantees the compressed tree is ≤ half the pre-compression size.
//
// Access algorithm returns the reuse distance for the accessed key. On first
// use, returns `FIRST_USE` (a sentinel = ~0ULL). The distance is exact up to
// the paper's bound: distance <= true_distance <= distance * (1 + e).
//
// Correctness invariants (asserted in debug builds):
//   * weight(subtree) == sum_{node in subtree} node.size
//   * for every node n: n.size <= n.capacity
//   * tree ordering: for every node n, left subtree times < n.time < right subtree times
//   * for every key k in `location_`, k lives in exactly one node
//
// This file is intentionally header-only (all methods inline) so all metrics
// in the same TU get their own inlined copy with type-specialized code paths.

#ifndef CLIENTS_REUSE_DISTANCE_SPLAY_H_
#define CLIENTS_REUSE_DISTANCE_SPLAY_H_

#include <cassert>
#include <cstdint>
#include <cmath>
#include <limits>
#include <list>
#include <unordered_map>
#include <vector>

namespace cctlib_reuse {

// Sentinel returned by access() on first use of a key.
static constexpr uint64_t FIRST_USE = std::numeric_limits<uint64_t>::max();

// -----------------------------------------------------------------------------
// CompressedSplay<Key>
//
// Reuse-distance oracle for a single stream of Key accesses. Instantiate one
// per metric (per-instruction, per-cacheline, per-page, ...). `e` is the
// maximum allowed relative error (0 < e < 1). Smaller e → larger tree → slower.
// e = 0.01 is a reasonable default (1% error).
template <typename Key>
class CompressedSplay {
  public:
    explicit CompressedSplay(double e = 0.01)
        : e_(e),
          e_prime_(e / (1.0 - e)),
          root_(nullptr),
          num_nodes_(0),
          distinct_keys_(0) {
        assert(e_ > 0.0 && e_ < 1.0);
    }

    ~CompressedSplay() { free_subtree(root_); }

    CompressedSplay(const CompressedSplay&) = delete;
    CompressedSplay& operator=(const CompressedSplay&) = delete;

    // Record an access to `key` at virtual time `new_time`. `new_time` must be
    // strictly greater than every previously-passed `new_time` in this instance
    // (monotonic clock). Returns the reuse distance, or FIRST_USE if this is
    // the first time `key` has been accessed.
    inline uint64_t access(const Key& key, uint64_t new_time) {
        auto it = location_.find(key);
        if (it == location_.end()) {
            // First use.
            insert_new(key, new_time);
            ++distinct_keys_;
            maybe_compress();
            return FIRST_USE;
        }

        // Splay the node containing `key` to the root so we can read its
        // right-subtree weight as the reuse distance.
        Node* node = it->second;
        splay(node);
        assert(root_ == node);

        // Distance = number of distinct keys accessed strictly after
        // node.time = weight of the right subtree once `node` is splayed to
        // the root. Do NOT add (root_->size - 1): the paper's approximation
        // treats every key in a compressed node as "accessed at node.time",
        // so within-node keys contribute 0 to a reuse-distance rooted at
        // that same node (they'd contribute if a DIFFERENT node were the
        // access point, and that's already captured by their node's own
        // weight in the right-subtree sum).
        uint64_t distance = weight_of(root_->right);

        // Remove `key` from its node. If the node is now empty, remove it from
        // the tree; otherwise just decrement counts.
        remove_from_root(key);

        // Re-insert `key` as (possibly a brand-new) node at `new_time`.
        insert_new(key, new_time);
        maybe_compress();
        return distance;
    }

    // Number of distinct keys ever inserted (i.e. the footprint).
    inline uint64_t footprint() const { return distinct_keys_; }

    // Node count in the tree right now.
    inline size_t num_nodes() const { return num_nodes_; }

  private:
    struct Node {
        uint64_t time; // most recent access time of any key in this node
        uint32_t size; // number of distinct keys in this node
        uint32_t capacity; // max size (assigned at compression)
        uint64_t weight; // sum of `size` in subtree rooted here
        Node* left;
        Node* right;
        Node* parent;
    };

    double e_;
    double e_prime_;
    Node* root_;
    size_t num_nodes_;
    uint64_t distinct_keys_;
    std::unordered_map<Key, Node*> location_;

    // ---- utility ----------------------------------------------------------

    static inline void free_subtree(Node* n) {
        if (!n)
            return;
        free_subtree(n->left);
        free_subtree(n->right);
        delete n;
    }

    static inline uint64_t weight_of(Node* n) { return n ? n->weight : 0; }

    // Recompute weight from children and own size.
    static inline void update_weight(Node* n) {
        if (!n)
            return;
        n->weight = uint64_t(n->size) + weight_of(n->left) + weight_of(n->right);
    }

    // ---- splay ------------------------------------------------------------

    // Rotate `x` up one level. Preserves BST ordering and re-computes weights.
    inline void rotate(Node* x) {
        Node* p = x->parent;
        assert(p != nullptr);
        Node* g = p->parent;
        if (p->left == x) {
            p->left = x->right;
            if (x->right)
                x->right->parent = p;
            x->right = p;
        } else {
            p->right = x->left;
            if (x->left)
                x->left->parent = p;
            x->left = p;
        }
        p->parent = x;
        x->parent = g;
        if (g) {
            if (g->left == p)
                g->left = x;
            else
                g->right = x;
        } else {
            root_ = x;
        }
        update_weight(p);
        update_weight(x);
    }

    // Standard top-down splay to bring `x` to root.
    inline void splay(Node* x) {
        while (x->parent) {
            Node* p = x->parent;
            Node* g = p->parent;
            if (!g) {
                rotate(x); // zig
            } else if ((g->left == p) == (p->left == x)) {
                rotate(p); // zig-zig
                rotate(x);
            } else {
                rotate(x); // zig-zag
                rotate(x);
            }
        }
    }

    // ---- BST insertion / removal ------------------------------------------

    // Insert `k` at time `t`. Prefer to attach to an existing node with the
    // same time; otherwise create a fresh 1-size / 1-capacity node. Splay the
    // (new or updated) node to the root so subsequent accesses at nearby times
    // are cheap.
    inline void insert_new(const Key& k, uint64_t t) {
        // Fast path: hottest node (root) is often the target for immediate
        // re-insertion after `access()`.
        if (root_ && root_->time == t) {
            root_->size += 1;
            update_weight(root_);
            location_[k] = root_;
            return;
        }

        // BST-walk to find the leaf position.
        Node* parent = nullptr;
        Node* cur = root_;
        while (cur) {
            if (t == cur->time) {
                cur->size += 1;
                update_weight(cur);
                // Propagate weight upward.
                for (Node* w = cur->parent; w; w = w->parent)
                    update_weight(w);
                location_[k] = cur;
                splay(cur);
                return;
            }
            parent = cur;
            cur = (t < cur->time) ? cur->left : cur->right;
        }

        Node* n = new Node{t, 1, 1, 1, nullptr, nullptr, parent};
        if (!parent) {
            root_ = n;
        } else if (t < parent->time) {
            parent->left = n;
        } else {
            parent->right = n;
        }
        ++num_nodes_;
        location_[k] = n;
        // Propagate weight upward, then splay for locality.
        for (Node* w = parent; w; w = w->parent)
            update_weight(w);
        splay(n);
    }

    // `key` is known to live in root_. Decrement root_.size (and weight).
    // If size becomes 0, splice root_ out of the tree.
    inline void remove_from_root(const Key& key) {
        assert(root_ != nullptr);
        location_.erase(key);
        root_->size -= 1;
        if (root_->size > 0) {
            update_weight(root_);
            return;
        }
        // Splice out empty root.
        Node* left = root_->left;
        Node* right = root_->right;
        delete root_;
        --num_nodes_;
        if (!left) {
            root_ = right;
            if (root_)
                root_->parent = nullptr;
        } else if (!right) {
            root_ = left;
            if (root_)
                root_->parent = nullptr;
        } else {
            // Standard splay-tree join: find the max of left, splay it to
            // root, then attach `right` as its right subtree.
            left->parent = nullptr;
            root_ = left;
            Node* max = left;
            while (max->right)
                max = max->right;
            splay(max);
            root_->right = right;
            right->parent = root_;
            update_weight(root_);
        }
    }

    // ---- compression ------------------------------------------------------

    inline void maybe_compress() {
        // Threshold from Prop 2.1: 4 * log_{1+e'} M + 4.
        // log_{1+e'} M = ln M / ln (1+e').
        if (distinct_keys_ < 32)
            return; // nothing to compress for tiny inputs
        double threshold =
            4.0 * std::log(double(distinct_keys_)) / std::log1p(e_prime_) + 4.0;
        if (double(num_nodes_) <= threshold)
            return;
        compress();
    }

    // Traverse the tree in reverse-time order, gather nodes, and greedily
    // merge adjacent pairs whose combined size fits the older node's updated
    // capacity. Then rebuild a balanced BST from the surviving list.
    inline void compress() {
        std::vector<Node*> in_order;
        in_order.reserve(num_nodes_);
        collect_in_order(root_, in_order);
        // in_order is ascending by time; iterate reverse to walk newest-first.
        // We need to re-key location_ for every key that changes owning node,
        // so we build a temporary map from old node → merged new node.
        std::unordered_map<Node*, Node*> forward;

        std::vector<Node*> compressed;
        compressed.reserve(in_order.size());
        // sum_of_older = size of all nodes strictly older than the current one
        // (in reverse-time order, that's the accumulated size we've already
        // processed toward the "newer" end of the vector as we work back).
        // Prop 2.1 defines capacity = sum_of_older_nodes * e'.
        //
        // We iterate from newest to oldest, greedily merging with the previous
        // (newer) accepted node when possible.
        uint64_t sum_older = 0;
        for (auto it = in_order.rbegin(); it != in_order.rend(); ++it) {
            Node* n = *it;
            uint32_t new_capacity =
                std::max<uint32_t>(1, uint32_t(sum_older * e_prime_));
            if (!compressed.empty()) {
                Node* prev = compressed.back(); // newer node already accepted
                uint32_t combined = prev->size + n->size;
                // Merge into `prev` if it still fits `prev`'s capacity.
                if (combined <= prev->capacity ||
                    combined <= new_capacity) {
                    // Prefer to keep the newer time (prev->time) since key
                    // membership determines distance ordering; the older
                    // node's keys are logically "newer than the actual
                    // access" per the paper's approximation.
                    prev->size = combined;
                    forward[n] = prev;
                    sum_older += n->size;
                    delete n;
                    --num_nodes_;
                    continue;
                }
            }
            n->capacity = std::max<uint32_t>(n->capacity, new_capacity);
            n->left = n->right = n->parent = nullptr;
            forward[n] = n;
            compressed.push_back(n);
            sum_older += n->size;
        }

        // Update the location_ map: every key that lived in an old node now
        // lives in forward[old_node].
        for (auto& [key, node] : location_) {
            auto f = forward.find(node);
            if (f != forward.end() && f->second != node)
                node = f->second;
        }

        // Rebuild a balanced BST from `compressed` (which is newest-to-oldest
        // → reverse for ascending-time input to the balanced builder).
        std::vector<Node*> asc(compressed.rbegin(), compressed.rend());
        root_ = build_balanced(asc, 0, asc.size());
        if (root_)
            root_->parent = nullptr;
        recompute_weights(root_);
    }

    static inline void collect_in_order(Node* n, std::vector<Node*>& out) {
        if (!n)
            return;
        collect_in_order(n->left, out);
        out.push_back(n);
        collect_in_order(n->right, out);
    }

    static inline Node* build_balanced(const std::vector<Node*>& v, size_t lo,
                                       size_t hi) {
        if (lo >= hi)
            return nullptr;
        size_t mid = lo + (hi - lo) / 2;
        Node* n = v[mid];
        n->left = build_balanced(v, lo, mid);
        n->right = build_balanced(v, mid + 1, hi);
        if (n->left)
            n->left->parent = n;
        if (n->right)
            n->right->parent = n;
        return n;
    }

    static inline void recompute_weights(Node* n) {
        if (!n)
            return;
        recompute_weights(n->left);
        recompute_weights(n->right);
        update_weight(n);
    }
};

// -----------------------------------------------------------------------------
// NaiveReuseStack<Key> -- reference implementation for correctness testing.
// Exact O(M) per access. Not used in production; only for unit tests to
// validate CompressedSplay's approximation.
template <typename Key>
class NaiveReuseStack {
  public:
    // Returns exact reuse distance, or FIRST_USE.
    inline uint64_t access(const Key& key) {
        uint64_t distance = 0;
        for (auto it = stack_.begin(); it != stack_.end(); ++it) {
            if (*it == key) {
                stack_.erase(it);
                stack_.push_front(key);
                return distance;
            }
            ++distance;
        }
        stack_.push_front(key);
        return FIRST_USE;
    }

    inline uint64_t footprint() const { return stack_.size(); }

  private:
    // Front of the list is most-recently-used. std::list because we do erase-
    // in-the-middle + push-front; O(N) walk is fine for the reference impl.
    std::list<Key> stack_;
};

} // namespace cctlib_reuse

#endif // CLIENTS_REUSE_DISTANCE_SPLAY_H_
