#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCKS 122
#define INDIRECT_BLOCKS 128

// Praveen driving, Eylam and Sashank navigating
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t direct[122];
    // 1 indirect pointer
    block_sector_t indirect;
    // 1 doubly indirect pointer
    block_sector_t doubly_indirect;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    bool isDir;                        /* True if file, false if directory */
    block_sector_t parent;              /* Parent directory */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */

    struct lock extend_lock;            /* Lock for extending file */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length) {
    if(pos < DIRECT_BLOCKS * BLOCK_SECTOR_SIZE) {
      // Return index in direct block
      return inode->data.direct[pos / BLOCK_SECTOR_SIZE];
    } else if(pos < (DIRECT_BLOCKS + INDIRECT_BLOCKS) * BLOCK_SECTOR_SIZE) {
      // Load indirect blocks
      block_sector_t indirect_block[128];
      block_read(fs_device, inode->data.indirect, indirect_block);

      // Return index in indirect block
      return indirect_block[(pos - DIRECT_BLOCKS * BLOCK_SECTOR_SIZE) /
      BLOCK_SECTOR_SIZE];
    } else {
      // Load doubly indirect blocks
      block_sector_t doubly_indirect_block[128];
      block_read(fs_device, inode->data.doubly_indirect,
      doubly_indirect_block);

      // Load indirect blocks
      block_sector_t indirect_block[128];
      block_read(fs_device, doubly_indirect_block[(pos - (DIRECT_BLOCKS + 
      INDIRECT_BLOCKS) * BLOCK_SECTOR_SIZE) / (BLOCK_SECTOR_SIZE * 128)], 
      indirect_block);

      // Return index in doubly indirect block
      return indirect_block[(pos - (DIRECT_BLOCKS + INDIRECT_BLOCKS) *
      BLOCK_SECTOR_SIZE) / BLOCK_SECTOR_SIZE];
    }
  }
  else
  return -1;
}
// end of Praveen driving

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

// Eylam driving, Praveen and Sashank navigating
/*
 * Returns whether allocating more space to an inode was successful
 *
 * pre: inode_disk *disk_inode is a valid pointer to an inode_disk struct to 
 * extend
 * off_t length is the length to extend the file
 * post: bool representing whether the extension was successful
 */
bool alloc_inode(struct inode_disk *disk_inode, off_t length) {
  size_t cur_blocks = bytes_to_sectors(disk_inode->length);
  uint32_t blocks_needed = bytes_to_sectors(length);

  // If we don't need to allocate any more blocks, return true
  if(blocks_needed == 0) {
    return true;
  }

  char zeros[BLOCK_SECTOR_SIZE] = {0};
  // There are remaining direct blocks
  if (DIRECT_BLOCKS - cur_blocks > 0) {
    // Calculate direct blocks possible to allocate
    uint32_t blocks_to_allocate = DIRECT_BLOCKS - cur_blocks;
    if (blocks_to_allocate > blocks_needed) {
      blocks_to_allocate = blocks_needed;
    }

    // Allocate direct blocks
    for(uint32_t i = cur_blocks; i < blocks_to_allocate; i++) {
      // Allocate a new block
      if(!free_map_allocate(1, &disk_inode->direct[i])) {
        return false;
      }

      // Write zeros to the block
      block_write(fs_device, disk_inode->direct[i], zeros);
    }

    // Update remaining blocks needed and current blocks
    blocks_needed -= blocks_to_allocate;
    cur_blocks += blocks_to_allocate;
  }

  // Return if we have allocated all blocks needed
  if(blocks_needed == 0) {
    disk_inode->length += length;
    return true;
  }
  
  // allocate blocks_needed indirect blocks
  if (cur_blocks < DIRECT_BLOCKS + INDIRECT_BLOCKS) {
    // Calculate indirect blocks possible to allocate
    uint32_t blocks_to_allocate = DIRECT_BLOCKS + INDIRECT_BLOCKS - cur_blocks;
    if (blocks_to_allocate > blocks_needed) {
      blocks_to_allocate = blocks_needed;
    }

    // indirect has never been used -> allocate it
    if(disk_inode->indirect == 0) {
      if(!free_map_allocate(1, &disk_inode->indirect)) {
        return false;
      }
    }

    block_sector_t indirect_block[128];
    block_read(fs_device, disk_inode->indirect, &indirect_block);

    // Allocate blocks_to_allocate indirect blocks
    uint32_t open_index =  cur_blocks - DIRECT_BLOCKS;
    for(uint32_t i = open_index; i < blocks_to_allocate; i++) {
      if(!free_map_allocate(1, &indirect_block[i])) {
        return false;
      }
      block_write(fs_device, indirect_block[i], zeros);
    }

    block_write(fs_device, disk_inode->indirect, &indirect_block);

    // Update remaining blocks needed and current blocks
    blocks_needed -= blocks_to_allocate;
    cur_blocks += blocks_to_allocate;
  }

  // Return if we have allocated all blocks
  if(blocks_needed == 0) {
    disk_inode->length += length;
    return true;
  }

  // allocate blocks_needed doubly indirect blocks
  if(cur_blocks < DIRECT_BLOCKS + INDIRECT_BLOCKS + INDIRECT_BLOCKS *
     INDIRECT_BLOCKS) {
    // Calculate doubly indirect blocks possible to allocate
    uint32_t blocks_to_allocate = DIRECT_BLOCKS + INDIRECT_BLOCKS +
    INDIRECT_BLOCKS * INDIRECT_BLOCKS - cur_blocks;
    if (blocks_to_allocate > blocks_needed) {
      blocks_to_allocate = blocks_needed;
    }

    // doubly indirect has never been used -> allocate it
    if(disk_inode->doubly_indirect == 0) {
      if(!free_map_allocate(1, &disk_inode->doubly_indirect)) {
        return false;
      }
    }

    block_sector_t doubly_indirect_block[INDIRECT_BLOCKS];
    block_read(fs_device, disk_inode->doubly_indirect, &doubly_indirect_block);


    // Determine where to start allocating from
    uint32_t open_index = (cur_blocks - (DIRECT_BLOCKS + INDIRECT_BLOCKS)) /
    INDIRECT_BLOCKS;
    uint32_t open_index2 = (cur_blocks - (DIRECT_BLOCKS + INDIRECT_BLOCKS)) %
    INDIRECT_BLOCKS;


    bool first_loop = true;

    // allocate blocks_needed indirect blocks
    for(uint32_t i = open_index; blocks_needed > 0 && 
        i < INDIRECT_BLOCKS; i++) {
      // indirect has never been used -> allocate it
      if(doubly_indirect_block[i] == 0) {
        if(!free_map_allocate(1, &doubly_indirect_block[i])) {
          return false;
        }
      }

      block_sector_t indirect_block[INDIRECT_BLOCKS];
      block_read(fs_device, doubly_indirect_block[i], &indirect_block);
      
      // allocate in 2nd level indirect blocks
      uint32_t j = first_loop ? open_index2 : 0;
      for(; blocks_needed > 0 && j < blocks_to_allocate; j++) {
        // Second level never used, allocate block
        if(!free_map_allocate(1, &indirect_block[j])) {
          return false;
        }

        // Write zeros to block and decrement blocks needed
        block_write(fs_device, indirect_block[j], zeros);
        blocks_needed--;
      }

      // write indirect block back to disk
      block_write(fs_device, doubly_indirect_block[i], &indirect_block);
    }

    // Write doubly indirect block
    block_write(fs_device, disk_inode->doubly_indirect, &doubly_indirect_block);
  } 

  disk_inode->length += length;
  return blocks_needed == 0;
}
// end of Eylam driving

// Sashank driving, Praveen and Eylam navigating
/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool isDir)
{
  struct inode_disk *disk_inode = NULL;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      /*
      allocate initial amount of blocks based on length
      update disk_inode->length = length
      */
      
      // Set inode properties to default
      disk_inode->magic = INODE_MAGIC;
      disk_inode->isDir = isDir;
      disk_inode->parent = ROOT_DIR_SECTOR;
      // allocate to initial size
      if(alloc_inode(disk_inode, length)) {
        block_write(fs_device, sector, disk_inode);
        return true;
      }
      free (disk_inode);
    }
  return false;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->extend_lock);
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  inode_lock(inode);
  if (inode != NULL)
    inode->open_cnt++;
  inode_unlock(inode);
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}
// end of Sashank driving

// Praveen driving, Eylam and Sashank navigating
/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  block_write (fs_device, inode->sector, &inode->data);

  inode_lock(inode);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      inode_unlock(inode);
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          // direct free
          size_t to_free = bytes_to_sectors(inode->data.length);
          for(int i = 0; to_free > 0 && i < DIRECT_BLOCKS ; i++) {
            free_map_release(inode->data.direct[i], 1);
            to_free--;
          }

          // indirect free
          if(to_free != 0) {
            block_sector_t block[INDIRECT_BLOCKS];
            block_read(fs_device, inode->data.indirect, &block);
            for(int i = 0; to_free > 0 && i < 128; i++) {
              free_map_release(block[i], 1);
              to_free--;
            }
          }

          
          if(!to_free != 0) {
            // doubly indirect free
            block_sector_t block2[INDIRECT_BLOCKS];
            block_read(fs_device, inode->data.doubly_indirect, &block2);
            for(int i = 0; to_free > 0 && i < INDIRECT_BLOCKS; i++) {
              block_sector_t block3[INDIRECT_BLOCKS];
              block_read(fs_device, block2[i], &block3);
              for(int j = 0; to_free > 0 && j < INDIRECT_BLOCKS; j++) {
                free_map_release(block3[j], 1);
                to_free--;
              }
            }
          }
          

          free_map_release (inode->sector, 1);
        }

      free (inode); 
    } else {
      inode_unlock(inode);
    }
}
// End of Praveen driving

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

// Sashank driving, Praveen and Eylam navigating
/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt) {
    return 0;
  }

  // Extend file if necessary
  if(inode_length (inode)  <= offset + size) {
    // Acquire lock
    bool lock_held = lock_held_by_current_thread (&inode->extend_lock);
    if (!lock_held)
      inode_lock(inode);

    
    // If extending fails, return 0
    if(!alloc_inode(&inode->data, offset + size)) {
      if (!lock_held)
        inode_unlock(inode);
      return bytes_written;
    }

    // Write back to disk
    inode->data.length = offset + size;
    block_write(fs_device, inode->sector, &inode->data);

    // Release lock
    if (!lock_held)
        inode_unlock(inode);
  }


  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
      ASSERT(bytes_written >= chunk_size);
    }
  free (bounce);

  return bytes_written;
}
// End of Sashank driving

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode_lock(inode);
  inode->deny_write_cnt++;
  inode_unlock(inode);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode_lock(inode);
  inode->deny_write_cnt--;
  inode_unlock(inode);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

// Eylam driving, Praveen and Sashank navigating
/* Acquires the release lock */
void inode_lock(struct inode *inode) {
  lock_acquire(&inode->extend_lock);
}

/* Releases the extend lock */
void inode_unlock(struct inode *inode) {
  lock_release(&inode->extend_lock);
}
// End of Eylam driving