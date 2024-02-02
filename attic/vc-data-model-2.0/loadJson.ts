import fs from 'fs'

const loadJson = (pathToFile: string) => {
  return JSON.parse(fs.readFileSync(pathToFile).toString())
}

export default loadJson