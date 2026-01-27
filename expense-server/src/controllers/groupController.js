const groupDao = require('../dao/groupDao');

const groupController = {

    create: async(req, res) => {
        try {
            const user = req.user;
            const { name, description, membersEmail, thumbnail } = req.body;

            let allMembers = [user.email];
            if (membersEmail && Array.isArray(membersEmail)) {
                allMembers = [...new Set([...allMembers, ...membersEmail])];
            }

            const group = await groupDao.createGroup({
                name,
                description,
                adminEmail: user.email,
                membersEmail: allMembers,
                thumbnail,
                paymentStatus: {
                    amount: 0,
                    currency: 'INR',
                    date: Date.now(),
                    isPaid: false
                }
            });

            res.status(201).json({ message: 'Group created', group });
        } catch (error) {
            res.status(500).json({ message: 'Internal server error' });
        }
    },

    updateGroup: async(req, res) => {
        try {
            const { groupId } = req.params;
            const updatedGroup = await groupDao.updateGroup(groupId, req.body);
            res.json(updatedGroup);
        } catch (error) {
            res.status(500).json({ message: 'Failed to update group' });
        }
    },

    addMembers: async(req, res) => {
        try {
            const { groupId } = req.params;
            const { members } = req.body;
            const group = await groupDao.addMembers(groupId, members);
            res.json(group);
        } catch (error) {
            res.status(500).json({ message: 'Failed to add members' });
        }
    },

    removeMembers: async(req, res) => {
        try {
            const { groupId } = req.params;
            const { members } = req.body;
            const group = await groupDao.removeMembers(groupId, members);
            res.json(group);
        } catch (error) {
            res.status(500).json({ message: 'Failed to remove members' });
        }
    },

    getGroupByEmail: async(req, res) => {
        try {
            const { email } = req.params;
            const groups = await groupDao.getGroupByEmail(email);
            res.json(groups);
        } catch (error) {
            res.status(500).json({ message: 'Failed to fetch groups' });
        }
    },

    getGroupByStatus: async(req, res) => {
        try {
            const { status } = req.params;
            const groups = await groupDao.getGroupByStatus(status === 'true');
            res.json(groups);
        } catch (error) {
            res.status(500).json({ message: 'Failed to fetch groups' });
        }
    },

    getAuditLog: async(req, res) => {
        try {
            const { groupId } = req.params;
            const audit = await groupDao.getAuditLog(groupId);
            res.json(audit);
        } catch (error) {
            res.status(500).json({ message: 'Failed to fetch audit log' });
        }
    }
};

module.exports = groupController;