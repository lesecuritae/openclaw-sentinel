import { g as globalApis } from './constants.-juJ8b_4.js';
import { i as index } from './index.OVGXnVRj.js';
import './run.CQOUYP-x.js';
import './index.M2dsQ_UQ.js';
import './tinyrainbow.Ht9iggcq.js';
import './display.pkpxlVcY.js';
import './pathe.M-eThtNZ.Clq7AXhv.js';
import './source-map.Dx3YPjIe.js';
import '../task-utils.js';
import './utils.DYj33du9.js';
import './spy.DPLvp2J7.js';
import 'chai';
import './plugins.Cigb0uSy.js';
import './offset.Dy-5Fdfn.js';
import './rpc.DWKX1ZbI.js';
import 'vite/module-runner';
import './index.DmDMHCg8.js';
import 'tinybench';
import 'expect-type';

function registerApiGlobally() {
	globalApis.forEach((api) => {
		// @ts-expect-error I know what I am doing :P
		globalThis[api] = index[api];
	});
}

export { registerApiGlobally };
