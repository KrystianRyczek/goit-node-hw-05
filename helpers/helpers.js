const fs = require("fs").promises;
const { Jimp } = require("jimp")
const path = require('path')



const tempDir = path.join(process.cwd(),'temp')
const storeImageDir=path.join(process.cwd(),'public/avatars')

const isAccessible = async (path) =>{
    return fs.access(path)
             .then(()=>true)
             .catch(()=>false)
}

const setupFolder = async (path)=>{
    const folderExist = await isAccessible(path)
    console.log(`access to: "${path}"- existed`, folderExist)

    if(!folderExist){
        try{
            await fs.mkdir(path)
        }catch(err){
            console.log("no permsion!")
            console.log(path)
            process.exit(1)
        }
    }
}
const MAX_AVATAR_WIDTH = 512
const MAX_AVATAR_HEIGHT = 512


// const isImageAndTransform = async (path) =>
//     new Promise((resolve) => {
//         Jimp.read(path, async (err, image) => {
//             if (err) resolve(false);

//             try {
//                 const w = image.bitmap.width;
//                 const h = image.bitmap.height;

//                 const cropWidth = w > MAX_AVATAR_WIDTH ? MAX_AVATAR_WIDTH : w;
//                 const cropHeight = h > MAX_AVATAR_HEIGHT ? MAX_AVATAR_HEIGHT : h;

//                 const centerX = Math.round(w / 2 - cropWidth / 2);
//                 const centerY = Math.round(h / 2 - cropHeight / 2);

//                 await image
//                     .rotate(360)
//                     .crop(
//                         centerX < 0 ? 0 : centerX,
//                         centerY < 0 ? 0 : centerY,
//                         cropWidth,
//                         cropHeight
//                     )
//                     .sepia()
//                     .write(path);
//                 resolve(true);
//             } catch (e) {
//                 console.log(e);
//                 resolve(false);
//             }
//         });
//     });




const isImageAndTransform = async (path) =>
        Jimp.read(path)
            .then( image => {
                //console.log(image.bitmap.width)
                try {
                    const w = image.bitmap.width;
                    const h = image.bitmap.height;
                        
                    const cropWidth = w > MAX_AVATAR_WIDTH ? MAX_AVATAR_WIDTH : w;
                    const cropHeight = h > MAX_AVATAR_HEIGHT ? MAX_AVATAR_HEIGHT : h;
    
                    const centerX = Math.round(w / 2 - cropWidth / 2)< 0 ? 0 : Math.round(w / 2 - cropWidth / 2);
                    const centerY = Math.round(h / 2 - cropHeight / 2)< 0 ? 0 : Math.round(h / 2 - cropHeight / 2);

                    image
                        .rotate(360)
//                         .crop(
// {                            h: centerX,
//                              w:centerY,
//                              x:cropWidth,
//                              y:cropHeight}
//                         )
                        .sepia()
                        .write(path);
                    return true;
                } catch (e) {
                    console.log(e);
                    return false;
                }
            }).catch(err => {
                console.log(err)
                return false;
              });


module.exports={setupFolder, isImageAndTransform, tempDir, storeImageDir}