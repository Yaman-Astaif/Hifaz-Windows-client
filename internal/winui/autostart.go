package winui

// BackgroundFlag is passed by the start-up entry the installer adds for all
// users (HKLM\...\Run). Started with it, the app stays in the tray, or exits
// at once if this user turned "start with Windows" off. The app itself never
// writes start-up entries, so removing Hifaz leaves none behind.
const BackgroundFlag = "--background"
