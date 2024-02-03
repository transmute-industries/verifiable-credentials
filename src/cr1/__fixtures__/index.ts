import fs from 'fs'

// vc
export const claimset_0 = fs.readFileSync('./src/cr1/__fixtures__/claimset-0.yml').toString()

// vp
export const claimset_1 = fs.readFileSync('./src/cr1/__fixtures__/claimset-1.yml').toString()

// // vc
// export const claimset_0_vc_jwt = JSON.parse(fs.readFileSync('./src/cr1/__fixtures__/issuer-0-vc-jwt.json').toString()).vc

// // vp
// export const claimset_1_vp_jwt = JSON.parse(fs.readFileSync('./src/cr1/__fixtures__/holder-0-vp-jwt.json').toString()).vp