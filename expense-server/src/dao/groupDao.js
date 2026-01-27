const Group = require('../model/group');

/**
 * Create group
 */
const createGroup = async(groupData) => {
    return await Group.create(groupData);
};

/**
 * Update group details
 */
const updateGroup = async(groupId, updateData) => {
    return await Group.findByIdAndUpdate(
        groupId,
        updateData, { new: true }
    );
};

/**
 * Add members to group
 */
const addMembers = async(groupId, members) => {
    return await Group.findByIdAndUpdate(
        groupId, { $addToSet: { membersEmail: { $each: members } } }, { new: true }
    );
};

/**
 * Remove members from group ✅
 */
const removeMembers = async(groupId, members) => {
    return await Group.findByIdAndUpdate(
        groupId, { $pull: { membersEmail: { $in: members } } }, { new: true }
    );
};

/**
 * Get groups by user email
 */
const getGroupByEmail = async(email) => {
    return await Group.find({
        membersEmail: email
    });
};

/**
 * Get groups by payment status ✅
 */
const getGroupByStatus = async(status) => {
    return await Group.find({
        'paymentStatus.isPaid': status
    });
};

/**
 * Get audit log (simple example) ✅
 */
const getAuditLog = async(groupId) => {
    const group = await Group.findById(groupId);
    if (!group) return null;

    return {
        groupId: group._id,
        createdAt: group.createdAt,
        adminEmail: group.adminEmail,
        membersCount: group.membersEmail.length,
        paymentStatus: group.paymentStatus
    };
};

module.exports = {
    createGroup,
    updateGroup,
    addMembers,
    removeMembers,
    getGroupByEmail,
    getGroupByStatus,
    getAuditLog
};