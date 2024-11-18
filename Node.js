const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const port = 3000;

// Set up multer for file upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage: storage });

// Create a directory for file uploads if it doesn't exist
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

// Endpoint to handle IPA signing
app.post('/sign-ipa', upload.fields([
  { name: 'ipaFile', maxCount: 1 },
  { name: 'p12File', maxCount: 1 },
  { name: 'mobileProvision', maxCount: 1 }
]), (req, res) => {
  const ipaFile = req.files['ipaFile'][0];
  const p12File = req.files['p12File'][0];
  const mobileProvision = req.files['mobileProvision'][0];
  const password = req.body.password;

  // Check if files are uploaded
  if (!ipaFile || !p12File || !mobileProvision || !password) {
    return res.status(400).send('Missing required files or password.');
  }

  // Step 1: Prepare the environment by extracting the .p12 certificate
  const p12Path = p12File.path;
  const ipaPath = ipaFile.path;
  const provisionPath = mobileProvision.path;
  const p12Password = password;

  // Step 2: Import the .p12 certificate using the password
  exec(`security import "${p12Path}" -P "${p12Password}" -T /usr/bin/codesign`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).send('Failed to import .p12 certificate: ' + stderr);
    }

    // Step 3: Sign the IPA file with the certificate and provisioning profile
    const signCommand = `xcrun -sdk iphoneos PackageApplication -v "${ipaPath}" -o "${ipaPath.replace('.ipa', '-signed.ipa')}" --sign "iPhone Distribution" --embed "${provisionPath}"`;

    exec(signCommand, (err, stdout, stderr) => {
      if (err) {
        return res.status(500).send('Error signing IPA: ' + stderr);
      }

      // Send the signed IPA back to the user
      const signedIpaPath = ipaPath.replace('.ipa', '-signed.ipa');
      res.download(signedIpaPath, 'signed-ipa.ipa', (err) => {
        if (err) {
          return res.status(500).send('Error downloading signed IPA.');
        }
        // Clean up uploaded files
        fs.unlinkSync(p12Path);
        fs.unlinkSync(ipaPath);
        fs.unlinkSync(provisionPath);
      });
    });
  });
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
