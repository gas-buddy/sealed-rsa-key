#!/usr/bin/env node
import minimist from 'minimist';
import create from './create-sealed-key';
import { startUnseal } from './unseal';

const argv = minimist(process.argv.slice(2), {
  boolean: [],
});

argv.shards = argv.shards || 7;
argv.threshold = argv.threshold || 4;
argv.kbfsroot = argv.kbfsroot || '/keybase';

async function run() {
  try {
    if (argv._[0] === 'create-sealed-key') {
      await create(argv);
    } else if (argv._[0] === 'start-unseal') {
      await startUnseal(argv);
    } else if (argv._[0] === 'host') {
      await host(argv);
    } else {
      await repl(argv);
    }
  } catch (error) {
    console.error(error.message);
    process.exit(-1);
  }
}

process.on('uncaughtRejection', () => {
  console.error('Uncaught rejection!');
});

run();
