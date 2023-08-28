import fs from 'fs'

const loadJson = (pathToFile) => {
  return JSON.parse(fs.readFileSync(pathToFile).toString())
}

export default loadJson