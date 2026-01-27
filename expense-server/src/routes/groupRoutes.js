const express = require('express');
const groupController = require('../controllers/groupController');
const authMiddleware = require('../middlewares/authMiddleware');

const router = express.Router();

/* Protected routes */
router.use(authMiddleware);

/* Group APIs */
router.post('/create', groupController.create);
router.put('/update/:groupId', groupController.updateGroup);
router.put('/add-members/:groupId', groupController.addMembers);
router.put('/remove-members/:groupId', groupController.removeMembers);

router.get('/by-email/:email', groupController.getGroupByEmail);
router.get('/by-status/:status', groupController.getGroupByStatus);
router.get('/audit/:groupId', groupController.getAuditLog);

module.exports = router;