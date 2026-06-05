import { createApp } from './server.js';
import { printStartupSummary } from './config.js';

const port = Number(process.env.PORT ?? 3000);
printStartupSummary();
createApp().listen(port, () => console.log(`didit-audit listening on :${port}`));
