#ifdef NVMMAP
/*
 * The mmap_lock() and mmap_unlock system calls.
 */
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/security.h>
#include <linux/mempolicy.h>
#include <linux/syscalls.h>
#include <linux/perf_event.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

/*
 * For a prot_numa update we only hold mmap_sem for read so there is a
 * potential race with faulting where a pmd was temporarily none. This
 * function checks for a transhuge pmd under the appropriate lock. It
 * returns a pte if it was successfully locked or NULL if it raced with
 * a transhuge insertion.
 */

static int vma_lock(struct vm_area_struct *vma)
{
	struct vm_area_struct *prev;
	unsigned long vm_flags, nstart, end, tmp, reqprot;
	unsigned long prot = PROT_NONE;
	//const int grows = prot & (PROT_GROWSDOWN|PROT_GROWSUP);
	int error;
	prot &= ~(PROT_GROWSDOWN|PROT_GROWSUP);
	if (!arch_validate_prot(prot))
		return -EINVAL;
	
	reqprot = prot;
	vm_flags = calc_vm_prot_bits(prot);
	prev = vma->vm_prev;
	end = vma->vm_end;

	nvmmap_log("[vma_lock] inode_vma : addr=%lx\n", vma->vm_start);

	down_write(&vma->vm_mm->mmap_sem);

	for (nstart = vma->vm_start ; ; ) {
		unsigned long newflags;

		vma->vm_mmap_flags |= VM_MMAP_LOCK;
		vma->vm_orig_flags = vma->vm_flags;
		vma->vm_orig_page_prot = vma->vm_page_prot;

		/* Here we know that vma->vm_start <= nstart < vma->vm_end. */

		newflags = vm_flags;
		newflags |= (vma->vm_flags & ~(VM_READ | VM_WRITE | VM_EXEC));

		/* newflags >> 4 shift VM_MAY% in place of VM_% */
		if ((newflags & ~(newflags >> 4)) & (VM_READ | VM_WRITE | VM_EXEC)) {
			error = -EACCES;
			goto out;
		}

		error = security_file_mprotect(vma, reqprot, prot);
		if (error)
			goto out;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mprotect_fixup(vma, &prev, nstart, tmp, newflags);
		if (error)
			goto out;
		nstart = tmp;

		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			goto out;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			goto out;
		}
	}
out:
	up_write(&vma->vm_mm->mmap_sem);
	return error;
}

int __mmap_lock(unsigned long addr)
{
	struct vm_area_struct *vma, *inode_vma;
	struct inode *inode;
	struct list_head *entry, *tmp;

	int error = -EINVAL;

	nvmmap_log("[__mmap_lock] addr=%lx\n", addr);

	if (addr & ~PAGE_MASK)
		return error;

	down_read(&current->mm->mmap_sem);

	vma = find_vma(current->mm, addr);
	error = -ENOMEM;
	if (!vma) {
		nvmmap_log("[__mmap_lock] I can not find the VMA\n");
		goto out;
	}
	up_read(&current->mm->mmap_sem);

	inode = vma->vm_file->f_inode;
	spin_lock(&inode->i_sync_lock);
	nvmmap_log("[__mmap_lock] spin lock ino=%lu\n", inode->i_ino);

	list_for_each_safe(entry, tmp, &inode->i_vma_list)
	{
		inode_vma = list_entry(entry, struct vm_area_struct, vm_inode_chain);
		error = vma_lock(inode_vma);
		if (error != 0)
			goto out;
	}
out:
	return error;
}

int __mmap_unlock(unsigned long addr)
{
	struct vm_area_struct *vma;
	struct inode *inode;

	int error = -EINVAL;

	nvmmap_log("[__mmap_unlock] addr=%lx\n", addr);

	if (addr & ~PAGE_MASK)
		return error;

	down_read(&current->mm->mmap_sem);

	vma = find_vma(current->mm, addr);
	error = -ENOMEM;
	if (!vma) {
		nvmmap_log("[__mmap_unlock] I can not find the VMA\n");
		return error;
	}
	up_read(&current->mm->mmap_sem);

	inode = vma->vm_file->f_inode;
	spin_unlock(&inode->i_sync_lock);

	return 0;
}

SYSCALL_DEFINE1(mmap_lock, unsigned long, addr)
{
	return __mmap_lock(addr);
}

SYSCALL_DEFINE1(mmap_unlock, unsigned long, addr)
{
	return __mmap_unlock(addr);
}
#endif	/* NVMMAP */
