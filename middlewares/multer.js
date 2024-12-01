const multer = require('multer')
const path = require('path')
const {tempDir, storeImageDir} = require('../helpers/helpers')
const {v4: uuidV4}= require('uuid')

const extensionWhiteList =[".jpg", ".jpeg", ".png", ".gif"]
const mimetypeWhiteList =["image/jpg", "image/jpeg", "image/png", "image/gif"]


const storage =multer.diskStorage({
    destination:(req, file, callBack) =>{
      callBack(null, tempDir)
    },
    filename:(req, file, callBack) =>{
      callBack(null, `${uuidV4()}${file.originalname}`)
    }
  })

  const uploadMiddleware = multer({
    storage,
    fileFilter: async (req, file, cb) => {
        const extension = path.extname(file.originalname).toLowerCase();
        const mimetype = file.mimetype;
        if (
            !extensionWhiteList.includes(extension) ||
            !mimetypeWhiteList.includes(mimetype)
        ) {
            return cb(null, false);
        }
        return cb(null, true);
    },
    limits: {
        fileSize: 1024 * 1024 * 5, // 5MB
    },
  });

  module.exports = {uploadMiddleware}