static inline void CopyRegionToShadowMemory(uint8_t * address, uint64_t length){
    uint64_t remainingBytesToCopy = length;
    uint8_t* curAddress = address;
    
    while(remainingBytesToCopy){
        uint8_t* showPageStartAddress = GetOrCreateShadowBaseAddress((uint64_t)address);
        uint8_t* shadowPageCopyBeginAddress = showPageStartAddress + PAGE_OFFSET((uint64_t)curAddress);
        uint64_t bytesToCopy = (remainingBytesToCopy < PAGE_SIZE ? remainingBytesToCopy : PAGE_SIZE);
        memcpy(shadowPageCopyBeginAddress, originalAddress, bytesToCopy);
        remainingBytesToCopy -= bytesToCopy;
        curAddress += bytesToCopy;
    }
}



// On each Load of an image copy the image data onto the shadow memory.
static VOID ImageLoad(IMG img, VOID* v) {
    uint32_t numRegions = IMG_NumRegions(img);
    // copy bytes of each region to shadow memory
    for(uint32_t regionIndex = 0 ; regionIndex < numRegions; regionIndex++){
        ADDRINT regionLowAddr = IMG_RegionLowAddress(img, regionIndex);
        /* Tells the highest address of any code or data loaded by the image. This is the address of the last byte loaded by the image. */
        ADDRINT regionHighAddr = IMG_RegionHighAddress(img, regionIndex);
        CopyRegionToShadowMemory((uint8_t*) regionLowAddr, regionHighAddr-regionLowAddr+1);
    }
}