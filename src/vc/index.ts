import sd from '@transmute/vc-jwt-sd'
import attached from './attached'
import validator from './validator'
import StatusList from './StatusList'
import sl from './sl'

const vc = { sd, sl, StatusList, validator, ...attached }

export default vc