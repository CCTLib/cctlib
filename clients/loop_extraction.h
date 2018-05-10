#ifndef __LOOP_EXTRACTION__
#define __LOOP_EXTRACTION__

#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "../src/splay-macros.h"

#define MAX_STRING_LENGTH (256)

struct LoopNode {
    uint64_t beginIP;
    LoopNode *parent;
    // vector<LoopNode *> children;
};

struct SplayNode {
    uint64_t key; // key = beginIP
    uint64_t beginIP;
    uint64_t endIP;
    SplayNode *left;
    SplayNode *right;
    LoopNode *loop;
};

struct FuncInfo {
    uint64_t beginIP;
    uint64_t endIP;
    LoopNode *loopRoot; 
    SplayNode *splayRoot;
};


// search the splay tree
inline SplayNode *splay(SplayNode *root, uint64_t key) {
  INTERVAL_SPLAY_TREE(SplayNode, root, key, beginIP, endIP, left, right);
  return root;
}


// insert a node into the splay tree
static inline void splayInsert(SplayNode *node, vector<FuncInfo> &Func) {
  uint64_t key = node->key;
  node->left = node->right = NULL;
  
  SplayNode *splayRoot = Func.back().splayRoot;

  if (splayRoot != NULL) {
    splayRoot = splay(splayRoot, key);

    if (key < splayRoot->key) {
      node->left = splayRoot->left;
      node->right = splayRoot;
      splayRoot->left = NULL;
    } else if (key > splayRoot->key) {
      node->left = splayRoot;
      node->right = splayRoot->right;
      splayRoot->right = NULL;
    } else {
	  printf("%p is already present!\n", node);
      assert(0);
    }
  }
  
  Func.back().splayRoot = node;
}


// delete the splay tree in the postorder traversal
inline void splayDelete(SplayNode **node) { 
    if (*node != NULL) {
        splayDelete(&((*node)->left));
        splayDelete(&((*node)->right));
        free(*node);
        *node = NULL;
    }
}


// parse functions in the XML file
static LoopNode *ParseFunc(char *addrString, vector<FuncInfo> &Func) {
    uint64_t ip;
    FuncInfo tmp;

    char *addr = strtok(addrString,"{[) -");
    ip = strtoull(addr, NULL, 16);
    tmp.beginIP = ip;
    
    addr = strtok(NULL,"{[)} -"); 
    ip = strtoull(addr, NULL, 16);
    tmp.endIP = ip;
    tmp.splayRoot = NULL;
    
    LoopNode *loopRoot = (LoopNode *) malloc(sizeof(LoopNode));
    loopRoot->parent = NULL;
    tmp.loopRoot = loopRoot;
    
    Func.push_back(tmp);
    
    return loopRoot;
}


// parse loops and statements in the XML file
static void ParseLoopAndState(xmlNode *a_node, LoopNode *parentLoop, vector<FuncInfo> &Func, unordered_map<uint64_t, char[MAX_STRING_LENGTH]> &LoopTable) {
    xmlNode *cur_node = NULL;
    
    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            char *addrString, *addr;
            if (!strcmp("L", (char *)cur_node->name)) { // parse loops 
                LoopNode *loop = (LoopNode *) malloc(sizeof(LoopNode));
            
                loop->parent = parentLoop;
            
                addrString = (char *)xmlGetProp(cur_node,(const xmlChar*)"v"); 
                addr = strtok(addrString,"{[)} -");
                uint64_t beginIP = strtoull(addr, NULL, 16); 
                loop->beginIP = beginIP;
                
                ParseLoopAndState(cur_node->children, loop, Func, LoopTable);
            
                char *filename = (char *)xmlGetProp(cur_node,(const xmlChar*)"f");
                char *lineNO = (char *)xmlGetProp(cur_node,(const xmlChar*)"l"); 
                snprintf(LoopTable[beginIP], MAX_STRING_LENGTH, "%s:%s", filename, lineNO);

            } else if (!strcmp("S", (char *)cur_node->name) && parentLoop->parent != NULL) { // parse statements
                
                addrString = (char *)xmlGetProp(cur_node,(const xmlChar*)"v"); 
                addr = strtok(addrString,"{[)} -");
                
                while (addr != NULL) {
                    SplayNode *splayNode = (SplayNode *) malloc(sizeof(SplayNode));
                    splayNode->key = splayNode->beginIP = strtoull(addr, NULL, 16); 
                    splayNode->loop = parentLoop;
                    
                    addr = strtok(NULL,"{[)} -"); // begin IP  
                    splayNode->endIP = strtoull(addr, NULL, 16); 
                    splayInsert(splayNode, Func);

                    addr = strtok(NULL,"{[)} -"); // end IP
                }
                
            } else if (parentLoop->parent != NULL) {
                ParseLoopAndState(cur_node->children, parentLoop, Func, LoopTable);
            }
        } else { 
            ParseLoopAndState(cur_node->children, parentLoop, Func, LoopTable);
        } 
    } 

}


// parse the XML file
static void Parse(xmlNode *a_node, vector<FuncInfo> &Func, unordered_map<uint64_t, char[MAX_STRING_LENGTH]> &LoopTable) {
    xmlNode *cur_node = NULL;
    LoopNode * loopRoot = NULL; 
        
    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (!strcmp((char*)cur_node->name, "P")) {
                char *addrString = (char *)xmlGetProp(cur_node,(const xmlChar*)"v"); 
                loopRoot = ParseFunc(addrString, Func);
                ParseLoopAndState(cur_node->children, loopRoot, Func, LoopTable);
            }
            else Parse(cur_node->children, Func, LoopTable); 
        }
        else Parse(cur_node->children, Func, LoopTable); 
    }
    
}


void ExtractLoopInfo(char const* filename, vector<FuncInfo> &Func, unordered_map<uint64_t, char[MAX_STRING_LENGTH]> &LoopTable) {
    xmlDoc *doc = NULL;
    xmlNode *rootElem = NULL;
    
    LIBXML_TEST_VERSION

    // parse the file and get the DOM
    doc = xmlReadFile(filename, NULL, 0);

    if (doc == NULL) {
        printf("error: could not parse file %s\n", filename);
        exit(-1);
    }

    // Get the root element node
    rootElem = xmlDocGetRootElement(doc);
    
    Parse(rootElem, Func, LoopTable);
    
    // free the document
    xmlFreeDoc(doc);

    xmlCleanupParser();
}

#endif
