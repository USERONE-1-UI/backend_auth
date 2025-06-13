const express = require('express');
const multer = require('multer');
const authMiddleware = require('../middlewares/authMiddlewares');

const { register, login, logout, getUsers, updateUser, deleteUser, updatePassword } = require('../controllers/authControllers');

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

router.post('/updatepassword', upload.none(), updatePassword);

router.get('/users', authMiddleware, getUsers);

router.put('/users/:id', authMiddleware, upload.single('image'), updateUser);

router.delete('/users/:id', authMiddleware, deleteUser);

module.exports = router;