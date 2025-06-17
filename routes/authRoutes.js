const express = require('express');
const multer = require('multer');
const authMiddleware = require('../middlewares/authMiddlewares');

const {
    register,
    login,
    logout,
    getUser,
    getUsers,
    updateUser,
    deleteUser,
    updatePassword,
    verifyCode,
    resetPassword
} = require('../controllers/authControllers');

const router = express.Router();

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    },
});

const upload = multer({ storage });

router.post('/register', upload.single('image'), register);

router.post('/login', upload.none(), login);

router.post('/logout', logout);

router.get('/user', authMiddleware, getUser);

router.post('/updatepassword', upload.none(), updatePassword);
router.post('/verifycode', upload.none(), verifyCode);
router.post('/resetpassword', upload.none(), resetPassword);

router.get('/users', authMiddleware, getUsers);

router.put('/users/:id', authMiddleware, upload.single('image'), updateUser);

router.delete('/users/:id', authMiddleware, deleteUser);

module.exports = router;