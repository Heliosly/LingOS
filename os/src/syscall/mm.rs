use alloc::{collections::BTreeMap, sync::Arc};
use polyhal::utils::addr;

use crate::{
    mm::{
        flush_all, get_target_ref,
        shm::{SharedMemorySegment, ShmIdDs, SHM_LOCK, SHM_UNLOCK},
        translated_byte_buffer, FrameTracker, MapArea, MapAreaType, MapPermission, MapType,
        MmapFlags, UserBuffer, VirtAddr, VirtPageNum,
    },
    syscall::flags::MsyncFlags,
    task::current_process,
    utils::error::{SysErrNo, SyscallRet},
};
pub async fn sys_shmat(shmid: i32, shmaddr: usize, shmflg: usize) -> SyscallRet {
    // 1. 获取共享段
    let segment_arc = {
        let manager = crate::mm::shm::SHM_MANAGER.lock().await;
        match manager.id_to_segment.get(&shmid) {
            Some(arc) => arc.clone(),
            None => return Err(SysErrNo::EINVAL),
        }
    };

    // 2. 准备映射
    let process = current_process();
    let mut ms = process.memory_set.lock();
    let segment = segment_arc.lock(); // 临时锁住以读取信息

    let page_count = segment.page_count();
    if page_count == 0 {
        return Ok(shmaddr);
    }

    // 3. 分配虚拟地址空间 (与之前相同)
    let start_vpn = ms
        .areatree
        .alloc_pages_from_hint(page_count, VirtAddr::from(shmaddr).ceil())
        .ok_or(SysErrNo::ENOMEM)?;
    let end_vpn = VirtPageNum(start_vpn.0 + page_count);

    // 4. 创建一个 SharedMemory 类型的 MapArea
    let perm = MapPermission::U | MapPermission::R | MapPermission::W; // 根据 shmflg 设置
    let map_area = MapArea::new_by_vpn(
        start_vpn,
        end_vpn,
        MapType::Framed,
        perm,
        MapAreaType::Shm { shmid },
    );

    // 5. 将共享段的物理帧逐个映射到 MapArea 的虚拟地址范围
    let map: BTreeMap<VirtPageNum, Arc<FrameTracker>> = segment
        .frames
        .iter()
        .enumerate()
        .map(|(i, frame)| (VirtPageNum(start_vpn.0 + i), (*frame).clone()))
        .collect();
    ms.push_with_given_frames(map_area, &map, false);

    drop(segment);
    segment_arc.lock().attach(process.pid.0 as u32);

    Ok(VirtAddr::from(start_vpn).0)
}

pub async fn sys_shmget(key: i32, size: usize, shmflg: usize) -> SyscallRet {
    let mut manager = crate::mm::shm::SHM_MANAGER.lock().await;

    // 校验 size
    if size > crate::config::MAX_SHM_SIZE {
        // 检查是否超过系统限制
        return Err(SysErrNo::EINVAL);
    }

    let is_create = (shmflg & crate::mm::shm::IPC_CREAT) != 0;
    let is_exclusive = (shmflg & crate::mm::shm::IPC_EXCL) != 0;

    // --- 情况 1: 查找一个已存在的段 (当 key 不是 IPC_PRIVATE) ---
    if key != crate::mm::shm::IPC_PRIVATE {
        if let Some(&shmid) = manager.key_to_id.get(&key) {
            // 键已存在
            if is_create && is_exclusive {
                // 如果同时指定了 IPC_CREAT 和 IPC_EXCL，但键已存在，则返回错误
                return Err(SysErrNo::EEXIST);
            }

            let segment_arc = manager.id_to_segment.get(&shmid).unwrap();
            let segment = segment_arc.lock();

            // 检查请求的大小是否超过了已存在段的大小
            if size > segment.id_ds.shm_segsz {
                return Err(SysErrNo::EINVAL);
            }
            // TODO: 一个完整的实现还需要在这里检查权限

            return Ok(shmid as usize);
        }
    }

    // --- 情况 2: 创建一个新的段 ---
    // 如果 key 不存在，但用户又没有指定 IPC_CREAT，则返回错误
    if !is_create && key != crate::mm::shm::IPC_PRIVATE {
        return Err(SysErrNo::ENOENT);
    }
    // 不能创建一个大小为 0 的段
    if size == 0 {
        return Err(SysErrNo::EINVAL);
    }

    let pid = current_process().pid.0;
    let new_segment = match SharedMemorySegment::new(key, size, pid) {
        Some(seg) => seg,
        None => return Err(SysErrNo::ENOMEM), // 物理帧分配失败
    };

    // 分配一个新的、唯一的 shmid
    let shmid = manager
        .next_id
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed) as i32;
    let segment_arc = Arc::new(crate::sync::Mutex::new(new_segment));

    // 将新段加入全局管理器
    manager.id_to_segment.insert(shmid, segment_arc);
    if key != crate::mm::shm::IPC_PRIVATE {
        manager.key_to_id.insert(key, shmid);
    }

    Ok(shmid as usize)
}

/// 功能: 控制一个共享内存段 (shmctl)
pub async fn sys_shmctl(shmid: i32, cmd: usize, buf: *mut ShmIdDs) -> SyscallRet {
    let mut manager = crate::mm::shm::SHM_MANAGER.lock().await;

    let pcb = current_process();
    let token = pcb.get_user_token().await;

    pcb.manual_alloc_type_for_lazy(buf).await?;

    let segment_arc = match manager.id_to_segment.get(&shmid) {
        Some(arc) => arc.clone(),
        None => return Err(SysErrNo::EINVAL),
    };

    let mut segment = segment_arc.lock();

    match cmd {
        crate::mm::shm::IPC_STAT => {
            if buf.is_null() || crate::mm::put_data(token, buf, segment.id_ds).is_err() {
                return Err(SysErrNo::EFAULT);
            }
            Ok(0)
        }
        crate::mm::shm::IPC_SET => {
            if buf.is_null() {
                return Err(SysErrNo::EFAULT);
            }
            let user_ds = *get_target_ref(token, buf)?;
            segment.id_ds.shm_perm.uid = user_ds.shm_perm.uid;
            segment.id_ds.shm_perm.gid = user_ds.shm_perm.gid;
            segment.id_ds.shm_perm.mode = user_ds.shm_perm.mode & 0o777;
            segment.id_ds.shm_ctime = crate::timer::get_time();
            Ok(0)
        }
        crate::mm::shm::IPC_RMID => {
            segment.marked_for_deletion = true;
            let key_to_remove = segment.id_ds.shm_perm.key;

            if segment.is_deletable() {
                if key_to_remove != crate::mm::shm::IPC_PRIVATE {
                    manager.key_to_id.remove(&key_to_remove);
                }
                manager.id_to_segment.remove(&shmid);
            }
            Ok(0)
        }
        SHM_LOCK | SHM_UNLOCK => Ok(0),
        _ => Err(SysErrNo::EINVAL),
    }
}

/// 功能: 分离一个共享内存段 (shmdt) - 新版
/// shmaddr: 由 shmat 返回的附加地址。
pub async fn sys_shmdt(shmaddr: usize) -> SyscallRet {
    let vaddr = VirtAddr::from(shmaddr);
    let process = current_process();
    let mut ms = process.memory_set.lock();

    // 1. 根据虚拟地址找到包含它的 MapArea
    let area_start = ms.areatree.find_area(vaddr.floor());
    let map_area = match area_start {
        Some(area_start) => ms.areatree.get(&area_start).unwrap(),
        _ => return Err(SysErrNo::EINVAL), // 地址不在任何已映射区域
    };

    // 2. 检查这是否是一个共享内存区域
    let shmid = if let MapAreaType::Shm { shmid } = map_area.area_type {
        shmid
    } else {
        // 地址合法，但不是一个共享内存映射
        return Err(SysErrNo::EINVAL);
    };

    // --- 关键逻辑：获取共享内存段的大小，以确定要解除映射的范围 ---
    let shm_page_count = {
        let manager = crate::mm::shm::SHM_MANAGER.lock().await;
        // 如果段已经被 IPC_RMID 删除了，这里可能找不到，但映射依然存在
        // 在这种情况下，我们仍然需要允许分离。
        // 为了简化，我们假设段总是能找到。一个更鲁棒的实现需要处理段已不在管理器中的情况。
        let segment_arc = manager.id_to_segment.get(&shmid).unwrap();
        let segment = segment_arc.lock().await;
        segment.page_count()
    };
    if shm_page_count == 0 {
        // 0大小的段，理论上 shmat 不会创建映射，但作为防御性编程
        return Ok(0);
    }

    // --- 计算要 unmap 的虚拟页范围 ---
    let start_vpn = vaddr.floor();
    let end_vpn = VirtPageNum(start_vpn.0 + shm_page_count);

    // 3. 检查要 unmap 的范围是否完全位于找到的 MapArea 内
    if !(map_area.vpn_range.get_start() <= start_vpn && end_vpn <= map_area.vpn_range.get_end()) {
        // 这通常不应该发生，如果发生了，说明内核状态不一致
        error!("shmdt: Inconsistent memory map state!");
        return Err(SysErrNo::EFAULT);
    }

    // 4. 根据 unmap 范围与 MapArea 的关系，进行拆分和移除
    let area_start = map_area.vpn_range.get_start();
    let area_end = map_area.vpn_range.get_end();

    if start_vpn == area_start && end_vpn == area_end {
        // --- 情况 A: 待 unmap 区域正好是整个 MapArea ---
        // 这是最简单的情况，直接移除整个 Area 即可
        ms.areatree.remove(&area_start); // area_start 就是 area_id
    } else if start_vpn == area_start {
        // --- 情况 B: 待 unmap 区域在 MapArea 的开头 ---
        // 需要将 MapArea 从 end_vpn 处切开，保留右半部分
        // | shm | remaining |
        // a_start=s_vpn   e_vpn   a_end
        let mut original_area = ms.areatree.get_mut(&area_start).unwrap();
        let right_part = original_area.split(end_vpn).await;
        // original_area 现在变成了左半部分（也就是要删除的 shm 部分）
        // 我们用新的 right_part 替换掉它
        ms.areatree.remove(&area_start); // 先移除旧的完整 area_id
        ms.areatree.push(right_part); // 再把保留的右半部分加回去
    } else if end_vpn == area_end {
        // --- 情况 C: 待 unmap 区域在 MapArea 的末尾 ---
        // 需要将 MapArea 从 start_vpn 处切开，保留左半部分
        // | remaining | shm |
        // a_start   s_vpn   a_end=e_vpn
        let mut original_area = ms.areatree.get_mut(&start_vpn).unwrap();
        // split 会修改 original_area, 使其成为左半部分，并返回右半部分
        let _right_part_to_be_removed = original_area.split(start_vpn).await;
        // 现在 original_area 就是我们要保留的部分，不需要做更多操作
        // 因为它的 area_id 没变，内容（vpn_range）已经被 split 修改了
    } else {
        // --- 情况 D: 待 unmap 区域在 MapArea 的中间 ---
        // | left | shm | right |
        // a_start  s_vpn e_vpn  a_end
        // 需要进行三次拆分
        let original_area = ms.areatree.get_mut(&start_vpn).unwrap();
        let (_mid_part_to_be_removed, right_part) = original_area.split3(start_vpn, end_vpn).await;
        // original_area 现在是左半部分 (left)
        // 我们需要把右半部分 (right_part) 添加回 area tree
        ms.areatree.push(right_part);
        // 中间部分 (mid_part_to_be_removed) 就被丢弃了
    }

    // 刷新页表（如果你的 unmap/split 没有自动做的话）
    flush_all();
    drop(ms); // 释放内存集锁

    // 5. 更新共享内存段的元数据
    let mut manager = crate::mm::shm::SHM_MANAGER.lock().await;
    let segment_arc = match manager.id_to_segment.get(&shmid) {
        Some(arc) => arc.clone(),
        None => return Ok(0), // 段已被删除，直接成功返回
    };

    let mut segment = segment_arc.lock();
    segment.detach(process.pid.0 as u32);

    if segment.is_deletable() {
        let key_to_remove = segment.id_ds.shm_perm.key;
        if key_to_remove != crate::mm::shm::IPC_PRIVATE {
            manager.key_to_id.remove(&key_to_remove);
        }
        manager.id_to_segment.remove(&shmid);
    }

    Ok(0)
}
pub async fn sys_msync(addr: usize, len: usize, flags: MsyncFlags) -> SyscallRet {
    info!("sys_msync: addr={}, len={}, flags={:?}", addr, len, flags);
    let addr = VirtAddr::from(addr);
    // 根据地址和长度，计算出所影响的虚拟页号范围
    let start_vpn: VirtPageNum = addr.floor();
    let end_vpn: VirtPageNum = (addr + len).ceil();

    // 在 areatree 中查找覆盖了给定地址范围的内存区域 (MapArea)
    // 这里我们假设给定的范围完全落在一个 MapArea 内
    let proc = current_process();
    let mut ms = proc.memory_set.lock().await;
    let crate::mm::MemorySet {
        areatree,
        page_table,
        ..
    } = &mut *ms;

    if let Some((_, area)) = areatree.iter_mut().find(|(_, area)| {
        area.vpn_range.get_start() <= start_vpn && end_vpn <= area.vpn_range.get_end()
    }) {
        // 检查这是否一个支持写回的 mmap 区域
        if area.area_type == MapAreaType::Mmap
            && area.mmap_flags.contains(MmapFlags::MAP_SHARED)
            && area.map_perm.contains(MapPermission::W)
        {
            if let Some(file) = &area.fd {
                // 准备将数据写回文件
                // 注意：这里的实现逻辑与您原始代码类似，直接使用起始地址和总长度。
                // 这种方式假设了需要同步的内存在虚拟地址空间上是连续的。
                let user_buffer = UserBuffer {
                    buffers: translated_byte_buffer(page_table.token(), addr.0 as *const u8, len),
                };

                // 根据 flags 执行写操作
                let write_future = file.file.write(user_buffer);

                if flags.contains(MsyncFlags::MS_SYNC) {
                    // MS_SYNC: 等待写操作完成
                    write_future.await?;
                } else if flags.contains(MsyncFlags::MS_ASYNC) {
                    // MS_ASYNC: 异步执行
                    // 在一个真正的操作系统内核中，这会把IO操作推入一个队列然后立即返回。
                    // 在 async Rust 的上下文中，我们可以选择生成一个任务去执行它而不阻塞当前流程。
                    // 为简化起见，我们这里仍然 await 它，但您可以根据您的执行器模型调整。
                    // 比如： your_executor::spawn(write_future);
                    write_future.await?;
                }

                // 处理 MS_INVALIDATE 标志
                // 这个标志要求使其他进程中对同一文件的映射失效。
                // 这通常需要一个复杂的全局数据结构来跟踪所有进程的文件映射 TODO(HELIOSLY)。
                // 一个简化的本地实现是使当前页表中的相关条目失效，以便下次访问时重新加载。
                if flags.contains(MsyncFlags::MS_INVALIDATE) {
                    for vpn in area.vpn_range.iter() {
                        area.data_frames.remove(&vpn);
                        if area.allocated(vpn) {
                            // 从页表中移除映射，这会使TLB失效
                            page_table.unmap(vpn);
                        }
                    }
                }
                Ok(0)
            } else {
                // 区域没有关联文件，无法写回
                Err(SysErrNo::ENOENT) // 或者返回一个更具体的错误码
            }
        } else {
            // 不是一个可写回的共享映射区域
            Ok(0)
        }
    } else {
        // 在给定的地址范围没有找到映射区域
        // 在Linux中，这会返回 ENOMEM
        Err(SysErrNo::ENOMEM) // 或者返回一个更具体的错误码
    }
}
