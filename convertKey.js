
import fs from "fs";;
const key = fs.readFileSync('./serviceAccountKey.json', 'utf8');
const base64 = Buffer.from(key).toString('base64');