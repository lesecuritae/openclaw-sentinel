import { w as workerInit } from '../chunks/init-threads.DbGO6vUd.js';
import { s as setupVmWorker, r as runVmTests } from '../chunks/vm.BQTVRi0W.js';
import 'node:worker_threads';
import '../chunks/init.BS957yFf.js';
import 'node:fs';
import 'node:module';
import 'node:url';
import 'vite/module-runner';
import '../chunks/index.1_nbEjJY.js';
import '../chunks/pathe.M-eThtNZ.Clq7AXhv.js';
import '../chunks/modules.BJuCwlRJ.js';
import '../chunks/utils.DYj33du9.js';
import '../path.js';
import 'node:path';
import '../module-evaluator.js';
import 'node:vm';
import '../traces.js';
import '@vitest/mocker';
import '@vitest/mocker/redirect';
import 'node:console';
import '../chunks/source-map.Dx3YPjIe.js';
import '../chunks/index.M2dsQ_UQ.js';
import '../chunks/tinyrainbow.Ht9iggcq.js';
import '../chunks/rpc.DWKX1ZbI.js';
import '../chunks/index.DmDMHCg8.js';
import '../chunks/inspector.CvyFGlXm.js';
import 'node:v8';
import '../chunks/console.CHi0lDgQ.js';
import 'node:stream';
import '../chunks/resolver.CBCHRZ7j.js';
import 'es-module-lexer';
import '../chunks/setup-common.D5-2VgqG.js';
import '../chunks/plugins.Cigb0uSy.js';

workerInit({
	runTests: runVmTests,
	setup: setupVmWorker
});
