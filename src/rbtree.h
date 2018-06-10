//
//  main.cpp
//  AugmentedRBTree
//
//  Created by Milind Chabbi on 5/26/18.
//  Copyright © 2018 Milind Chabbi. All rights reserved.
//

#include <iostream>
#include <stdint.h>


enum COLOR {BLACK=0, RED=1};

template<class K, class V, class S>
struct TreeNode{
    TreeNode * left;
    TreeNode * right;
    TreeNode * parent;
    COLOR color;
    K key;
    V value;
    S sum;
    TreeNode(K k, V v): key(k), value(v) {}
};

template<class K, class V, class S>
class RBTree{
    using TNKV = TreeNode<K, V, S>;
private:
    TreeNode<K, V, S> * root;
public:
    RBTree(): root(0) {
        
    }
    
    TNKV * InsertBST(TNKV * newNode){
        V inc = newNode->value;
        newNode->left = newNode->right = newNode->parent = NULL;
        // always begin with a red color node
        newNode->color = RED;
        newNode->sum = inc;
        
        if(root == NULL) {
            root = newNode;
            return newNode;
        }
        
        TNKV * cur = root;
        TNKV * parent = NULL;

        while(cur) {
            parent = cur;
            parent->sum += inc;
            if (newNode->key <= cur->key) {
                cur = cur->left;
            } else if (newNode->key > parent->key){
                cur = cur->right;
            }
        }
        
        if (newNode->key < parent->key) {
            assert(parent->left == NULL);
            parent->left = newNode;
        } else {
            assert(parent->right == NULL);
            parent->right = newNode;
        }
        newNode->parent = parent;
        return  newNode;
    }

    TNKV * FindSumGreaterEqual(K key, S *sum) {
        *sum = 0;
        if(root == NULL) {
            return NULL;
        }
        
        TNKV * cur = root;
        TNKV * parent = NULL;

        while(cur) {
            parent = cur;
            if (key < cur->key) {
                *sum += cur->value + (cur->right?cur->right->sum : 0);
                cur = cur->left;
            } else if (key > cur->key){
                cur = cur->right;
            } else {
                *sum += cur->value + (cur->right?cur->right->sum : 0);
                break;
            }
        }
        // if cur is null we found none
        return  cur;
    }

    TNKV * FindSumGreaterThan(K key, S *sum) {
        *sum = 0;
        if(root == NULL) {
            return NULL;
        }
        
        TNKV * cur = root;
        TNKV * parent = NULL;

        while(cur) {
            parent = cur;
            if (key < cur->key) {
                *sum += cur->value + (cur->right?cur->right->sum : 0);
                cur = cur->left;
            } else if (key > cur->key){
                cur = cur->right;
            } else {
                *sum += (cur->right?cur->right->sum : 0);
                break;
            }
        }
        // if cur is null we found none
        return  cur;
    }
    
    void UpdateSum(TNKV * node){
        node->sum = node->value + (node->left?node->left->sum:0) + (node->right?node->right->sum:0);
    }

    COLOR GetColor(TNKV * const node){
        if(node){
            return node->color;
        }
        return BLACK;
    }

    void SetColor(TNKV * node, COLOR color){
        if(node){
            node->color = color;
        }
    }

    COLOR GetColorUnconditional(TNKV * const node){
        assert(node);
        return node->color;
    }

    void SetColorUnconditional(TNKV * node, COLOR color){
        assert(node);
        node->color = color;
    }

    
    // https://www.geeksforgeeks.org/c-program-red-black-tree-insertion/
    // https://www.youtube.com/watch?v=6QOKk_pcv3U
    /* . ==> red node
                       g                                      p
                   /       \                              /       \
                  u        p.                            g.         x.
                /  \       / \            ==>           /  \      /   \
              T1     T2   T3  x.                       u   T3    T4    T5
                              /\                      /\
                            T4  T5                   T1 T2
     */

    
    // We get a pointer to the right child, which will be rotated anticlockwise around its parent.
    void RotateLeft(TNKV * p){
        assert(p->parent);
        // is it really needed?
        //assert(p->parent->right);
        assert(p->parent->right == p);
        auto g = p->parent;
        //auto u = g->right;
        auto ggp = g->parent;

        p->parent = g->parent;
        g->parent = p;
        g->right = p->left;
        if (p->left) {
            p->left->parent = g;
        }
        p->left = g;
        
        if (ggp) {
            if (ggp->left == g)
                ggp->left = p;
            else
                ggp->right = p;
        } else {
            root = p;
        }
        // Adjust the sum
        // u is unchanged
        // x is unchanged
        UpdateSum(g);
        UpdateSum(p);

    }

    /* . ==> red node
                g                                      x
            /       \                              /       \
           u         p.                            g.         p.
          /  \       / \            ==>           /  \      /   \
       T1     T2   x.   T5                       u   T3    T4    T5
                  /\                            /\
                 T3  T4                        T1 T2
*/

    
    // We get a pointer to x. It will be rotaed clockwise around its parent and then anticlockwise around the new parent.
    void RotateRightThenLeft(TNKV * x){
        assert(x->parent);
        // is it really needed?
        assert(x->parent->parent);
        assert(x->parent->left == x);
        assert(x->parent->parent->right == x->parent);
        auto g = x->parent->parent;
        auto p = x->parent;
        auto ggp = g->parent;
        
        g->right = x->left;
        if (x->left) {
            x->left->parent = g;
        }
        p->left = x->right;
        if(x->right) {
            x->right->parent = p;
        }
        p->parent = x;
        g->parent = x;
        x->right = p;
        x->left = g;
        x->parent = ggp;
        if (ggp) {
            if (ggp->left == g)
                ggp->left = x;
            else
                ggp->right = x;
        } else {
            root = x;
        }
        
        // Adjust the sum
        // u is unchanged
        UpdateSum(p);
        UpdateSum(g);
        UpdateSum(x);

    }

    
    /*
                         g                                      p
                     /       \                              /       \
                    p.        u                            x.         g.
                  /  \       / \            ==>           /  \      /   \
                x.    T3    T4  T5                      T1   T2    T3    u
               /\                                                        /\
             T1  T2                                                     T4 T5
     
     */

    // We get pointer to the left child.
    // We rotate the node clockwise wrt to its parent.
    void RotateRight(TNKV * p){
        assert(p->parent);
        // is it really needed?
        // assert(p->parent->right);
        assert(p->parent->left == p);
        auto g = p->parent;
        //auto u = g->right;
        auto ggp = g->parent;
        p->parent = g->parent;
        g->parent = p;
        g->left = p->right;
        if (p->right) {
            p->right->parent = g;
        }
        p->right = g;
        
        if (ggp) {
            if (ggp->left == g)
                ggp->left = p;
            else
                ggp->right = p;
        } else {
            root = p;
        }
        
        // Adjust the sum
        // u is unchanged
        // x is unchanged
        UpdateSum(g);
        UpdateSum(p);
    }

    /*
                g                                      x
            /       \                              /       \
           p.        u                            p.         g.
         /  \       / \            ==>           /  \      /   \
        T1    x.    T4  T5                      T1   T2    T3    u
             /\                                                  /\
           T2  T3                                               T4 T5
     
     */

    // x is the right child.
    // Effectively, we rotate x anticlockwise around its parent and then clockwise around the new parent.
    void RotateLeftThenRight(TNKV * x){
        assert(x->parent);
        // is it really needed?
        assert(x->parent->parent);
        assert(x->parent->right == x);
        assert(x->parent->parent->left == x->parent);
        auto g = x->parent->parent;
        auto p = x->parent;
        auto ggp = g->parent;

        g->left = x->right;
        if (x->right) {
            x->right->parent = g;
        }
        p->right = x->left;
        if(x->left) {
            x->left->parent = p;
        }
        p->parent = x;
        g->parent = x;
        x->left = p;
        x->right = g;
        x->parent = ggp;
        if (ggp) {
            if (ggp->left == g)
                ggp->left = x;
            else
                ggp->right = x;
        } else {
            root = x;
        }
        // Adjust the sum
        // u is unchanged
        UpdateSum(p);
        UpdateSum(g);
        UpdateSum(x);
    }

    void BalanceInsertion(TNKV * x){
        if (! x->parent) {
            // reached root, color it black
            x->color = BLACK;
            return;
        }
        // Do we have a double red problem?
        if (x->parent->color == BLACK) {
            return; // no problem
        }
        
        // since parent is red, there must be grand parent
        auto p = x->parent;
        auto g = x->parent->parent;
        // is p left of g
        if (p == g->left) {
            // is uncle red? if so, recolor
            auto u = g->right;
            if (u && (u->color == RED)){
                SetColorUnconditional(g, RED);
                SetColorUnconditional(u, BLACK);
                SetColorUnconditional(p, BLACK);
                // x will remain red.
                BalanceInsertion(g);
            } else {
                // is x left of p?
                if(p->left == x) {
                    RotateRight(p);
                    //Recolor
                    // x = g = red.
                    // p = black
                    SetColorUnconditional(x, RED);
                    SetColorUnconditional(g, RED);
                    SetColorUnconditional(p, BLACK);
                    // end of protocol on a rotation
                } else {
                    assert(p->right == x);
                    RotateLeftThenRight(x);
                    SetColorUnconditional(p, RED);
                    SetColorUnconditional(g, RED);
                    SetColorUnconditional(x, BLACK);
                    // end of protocol on a rotation
                }
            }
        } else {
            // p is right child of g
            assert(p == g->right);
            
            // is uncle red? if so, recolor
            auto u = g->left;
            if (u && (u->color == RED)){
                SetColorUnconditional(g, RED);
                SetColorUnconditional(u, BLACK);
                SetColorUnconditional(p, BLACK);
                // x will remain red.
                BalanceInsertion(g);
            } else {
                // is x right of p?
                if(p->right == x) {
                    RotateLeft(p);
                    SetColorUnconditional(x , RED);
                    SetColorUnconditional(g /*now the new sibling */, RED);
                    SetColorUnconditional(p /*now the new sibling */, BLACK);
                    // end of protocol on a rotation
                } else {
                    assert(p->left == x);
                    RotateRightThenLeft(x);
                    //Recolor
                    // p = g = red.
                    // x = black
                    SetColorUnconditional(p, RED);
                    SetColorUnconditional(g, RED);
                    SetColorUnconditional(x, BLACK);
                    // end of protocol on a rotation
                }
            }
        }
    }
    
    void Insert(TNKV * newNode){
        InsertBST(newNode);
        BalanceInsertion(newNode);
    }

    void BalanceDeletion(TNKV * node){
        // Deleting a red node is harmless (does not change the black depth).
        if (node->color == RED) {
            return;
        }
        
        // Node is BLACK. If it has at least one RED child, recoloring the child with BLACK will fix the height problem.
        // TODO: it can only have the right child.
        if (GetColor(node->left) == RED || GetColor(node->right) == RED) {
            TNKV *child = node->left != nullptr ? node->left : node->right;
                SetColorUnconditional(child, BLACK);
                return;
        }
        
        // Series of harder cases where node is black and it has no red children.
        
        TNKV *sibling = nullptr;
        TNKV *parent = nullptr;
        TNKV *ptr = node;
        while (ptr != root) {
            parent = ptr->parent;
            if (ptr == parent->left) {
                // Left subtree shrank in height
                sibling = parent->right;
                if (GetColor(sibling) == RED) {
                    SetColor(sibling, BLACK);
                    SetColor(parent, RED);
                    RotateLeft(sibling);
                } else {
                    if ((!sibling) ||
                        (GetColor(sibling->left) == BLACK && GetColor(sibling->right) == BLACK)) {
                        
                        if(sibling) {
                            SetColorUnconditional(sibling, RED);
                        }
                        
                        if(GetColorUnconditional(parent) == RED) {
                            SetColorUnconditional(parent, BLACK);
                        } else {
                            SetColorUnconditional(parent, BLACK);
                            ptr = parent;
                            continue;
                        }
                    } else {
                        if (GetColor(sibling->right) == BLACK) {
                            SetColorUnconditional(sibling->left, parent->color);
                            SetColorUnconditional(parent, BLACK);
                            RotateRightThenLeft(sibling->left);
                        } else {
                            SetColorUnconditional(sibling, parent->color);
                            SetColorUnconditional(parent, BLACK);
                            SetColorUnconditional(sibling->right, BLACK);
                            RotateLeft(sibling);
                        }
                    }
                }
            } else {
                // Right subtree shrank in height
                sibling = parent->left;
                if (GetColor(sibling) == RED) {
                    SetColor(sibling, BLACK);
                    SetColor(parent, RED);
                    RotateRight(sibling);
                } else {
                    if ( (!sibling) ||
                        (GetColor(sibling->left) == BLACK && GetColor(sibling->right) == BLACK)) {
                       
                        if (sibling){
                            SetColorUnconditional(sibling, RED);
                        }

                        if (GetColorUnconditional(parent) == RED) {
                            SetColorUnconditional(parent, BLACK);
                        } else {
                            SetColorUnconditional(parent, BLACK);
                            ptr = parent;
                            continue;
                        }
                    } else {
                        if (GetColor(sibling->left) == BLACK) {
                            SetColorUnconditional(sibling->right, parent->color);
                            SetColorUnconditional(parent, BLACK);
                            RotateLeftThenRight(sibling->right);
                        } else {
                            SetColorUnconditional(sibling, parent->color);
                            SetColorUnconditional(parent, BLACK);
                            SetColorUnconditional(sibling->left, BLACK);
                            RotateRight(sibling);
                        }
                    }
                }
            }
            break;
        }
        SetColorUnconditional(root, BLACK);
    }

    TNKV * DeleteHelper(TNKV * node){
        // Case 1: no children
        if (node->left == NULL && node->right==NULL) {
            if (node == root) {
                root = NULL;
            } else {
                TNKV ** whomToUpdate = (node->parent->left == node) ? (& node->parent->left) : (& node->parent->right);
                *whomToUpdate=NULL;
            }
            return node;
        }
        // Case 2: single child
        if (node->left == NULL || node->right == NULL) {
            TNKV * parent = node->parent;

            TNKV * theChild = (node->left) ? (node->left) : (node->right);
            if (parent) {
                TNKV ** theParentLoc = (parent->left == node) ? (& parent->left) : (& parent->right);
                *theParentLoc = theChild;
            } else {
                root = theChild;
            }
            theChild->parent = parent;
            return node;
        }
        // Case 3: both children

        // Get the in-order successor
        
        TNKV * curParent = NULL;
        for(TNKV * cur = node->right; cur != NULL; cur = cur->left){
            curParent = cur;
        }
        
        V dec = curParent->value;
        // Update the sum since this subtree lost a node
        for (TNKV * cur = curParent->parent; cur != node; cur = cur->parent) {
            cur->sum -= dec;
        }
        
        // swap curParent with node
        auto tmp1 = node->key;
        node->key = curParent->key;
        curParent->key = tmp1;
        
        auto tmp2 = node->value;
        node->value = curParent->value;
        curParent->value = tmp2;
        
        // Now, delete curParent
        return DeleteHelper(curParent);
    }
    
    TNKV * WhichNodeToDelete(TNKV * node){
        // Case 1: no or single single child
        if (node->left == NULL || node->right == NULL) {
            node->sum = 0;
            if (node->left != NULL) {
                node->sum += node->left->sum;
            }
            if (node->right != NULL) {
                node->sum += node->right->sum;
            }
            return node;
        }
        // Get the in-order successor
        
        TNKV * curParent = NULL;
        for(TNKV * cur = node->right; cur != NULL; cur = cur->left){
            curParent = cur;
        }
        
        V dec = curParent->value;
        // Update the sum since this subtree lost a node
        for (TNKV * cur = curParent->parent; cur != node; cur = cur->parent) {
            cur->sum -= dec;
        }
        
        // swap curParent with node
        auto tmp1 = node->key;
        node->key = curParent->key;
        curParent->key = tmp1;
        
        auto tmp2 = node->value;
        node->value = curParent->value;
        curParent->value = tmp2;
        
        // Now, delete curParent
        return WhichNodeToDelete(curParent);
    }

    TNKV * Delete(TNKV * node){
        V dec = node->value;
        // decrement this value from parents
        for(TNKV * cur = node; cur; cur = cur->parent){
            cur->sum -= dec;
        }
//        auto delNode =  DeleteHelper(node);
        auto delNode = WhichNodeToDelete(node);
        BalanceDeletion(delNode);
        assert(delNode->left == NULL || (delNode->right == NULL));
        if (delNode->parent) {
            if (delNode->parent->left == delNode) {
                if(delNode->right) {
                    delNode->parent->left = delNode->right;
                    delNode->right->parent = delNode->parent;
                } else if (delNode->left) {
                    delNode->parent->left = delNode->left;
                    delNode->left->parent = delNode->parent;
                } else {
                    delNode->parent->left = NULL;
                }
            } else {
                if(delNode->right) {
                    delNode->parent->right = delNode->right;
                    delNode->right->parent = delNode->parent;
                } else if (delNode->left){
                    delNode->parent->right = delNode->left;
                    delNode->left->parent = delNode->parent;
                } else {
                    delNode->parent->right = NULL;
                }
            }
        } else {
            if(delNode->right) {
                root = delNode->right;
                delNode->right->parent = NULL;
            } else if(delNode->left) {
                root = delNode->left;
                delNode->left->parent = NULL;
            } else {
                root = NULL;
            }
        }
        return delNode;
    }
    
    bool IsBSTHelper(TNKV* node){
        if (!node)
            return true;
        
        if(node->left) {
            if (node->left->key > node->key)
                return false;
        }
        
        if(node->right) {
            if (node->right->key <= node->key)
                return false;
        }
        
        return IsBSTHelper(node->left) && IsBSTHelper(node->right);
    }
    
    bool IsBST(){
        if (!root)
            return true;
        
        return IsBSTHelper(root);
    }

    bool IsSumCorrectHeler(TNKV * node, V & curSum){
        if (node == NULL) {
            curSum = 0;
            return  true;
        }
        
        V lSum = node->left? node->left->sum : 0;
        V rSum = node->right? node->right->sum : 0;
        if ((lSum + rSum + node->value) != node->sum) {
            return false;
        }
        
        if(! IsSumCorrectHeler(node->left, lSum))
            return false;
        if(! IsSumCorrectHeler(node->right, rSum))
            return false;
        
        if ((lSum + rSum + node->value) != node->sum) {
            return false;
        }
        curSum = lSum + rSum + node->value;
        return true;
    }

    bool IsSumCorrect(){
        V curSum;
        if (!root)
            return true;
        
        return IsSumCorrectHeler(root, curSum);
    }
    
    bool IsTreeCorrectHeler(TNKV * node){
        if (node == NULL) {
            return  true;
        }
        
        if (node->left) {
            if (node->left->parent != node)
                return false;
        }

        if (node->right) {
            if (node->right->parent != node)
                return false;
        }

        if (node->color == RED && (! node->parent || node->parent->color == RED)){
            return false;
        }
        
        return IsTreeCorrectHeler(node->left) && IsTreeCorrectHeler(node->right);
    }


    bool IsTreeCorrect(){
        if (!root)
            return true;
        
        return IsTreeCorrectHeler(root);
    }

    bool IsReachableHelper(TNKV * root, TNKV * target){
        if (!root) {
            return false;
        }
        
        if (root == target)
            return true;
        auto l = IsReachableHelper(root->left, target) ;
        auto r = IsReachableHelper(root->right, target) ;
        if (l && !r)
            return true;
        if (!l && r)
            return true;
        return false;
    }

    bool IsReachable(TNKV * target){
        return IsReachableHelper(root, target);
    }
};

#if RBTREE_TEST
#define N (1L<<12)

void Test1(){
    RBTree<uint64_t, uint64_t> rbt;
    
    uint32_t * k = new uint32_t[N];
    uint32_t * v = new uint32_t[N];
    TreeNode<uint64_t, uint64_t> ** tn = new TreeNode<uint64_t, uint64_t>*[N]();

    for (int i = 0; i < N; i ++) {
        k[i] = uint32_t(rand());
        v[i] = uint32_t(rand());
    }

    for (int i = 0; i < N; i ++) {
        TreeNode<uint64_t, uint64_t> * t = new TreeNode<uint64_t, uint64_t>(k[i], v[i]);
        //t->key = k[i];
        //t->value = v[i];
        tn[i] = t;
        rbt.Insert(t);
        assert(rbt.IsBST());
        assert(rbt.IsSumCorrect());
        assert(rbt.IsTreeCorrect());
        
        volatile int pp = 1;
        if (pp && (i > 0) && (i%100 == 0)) {
            int j = uint32_t(rand()) % i;
            auto d = rbt.Delete(tn[j]);
            assert(rbt.IsBST());
            assert(rbt.IsSumCorrect());
            assert(rbt.IsTreeCorrect());
            rbt.Insert(d);
            assert(rbt.IsBST());
            assert(rbt.IsSumCorrect());
            assert(rbt.IsTreeCorrect());
        }
    }

    for (int i = 0; i <  N; i ++) {
        int j = i;//uint32_t(rand()) % N;
        if (tn[j]) {
            auto nn = rbt.Delete(tn[j]);
            for (int k = 0; k < N; k ++) {
                if (tn[k] == nn) {
                    tn[k] = 0;
                    break;
                }
            }
        }
        for (int k = 0; k < N; k ++) {
            if (tn[k]) {
                assert(rbt.IsReachable(tn[k]));
            }
        }
        assert(rbt.IsBST());
        assert(rbt.IsSumCorrect());
        assert(rbt.IsTreeCorrect());
    }

    
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Hello, World!\n";
    Test1();
    std::cout << "Great, World!\n";
    return 0;
}
#endif // RBTREE_TEST

