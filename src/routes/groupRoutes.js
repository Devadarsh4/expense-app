const express = require('express');
const groupController = require('../controllers/groupController');
const { protect, authorize } = require('../middlewares/authMiddleware');

const router = express.Router();

/* Protected routes */
router.use(protect);

/* Group APIs */
router.get('/my-groups', authorize('group:view'), groupController.getMyGroups);
router.post('/create', authorize('group:create'), groupController.create);
router.put('/update/:groupId', authorize('group:update'), groupController.updateGroup);
router.put('/add-members/:groupId', authorize('group:update'), groupController.addMembers);
router.put('/remove-members/:groupId', authorize('group:update'), groupController.removeMembers);

router.get('/by-email/:email', authorize('group:view'), groupController.getGroupByEmail);
router.get('/by-status/:status', authorize('group:view'), groupController.getGroupByStatus);
router.get('/audit/:groupId', authorize('group:view'), groupController.getAuditLog);

module.exports = router;