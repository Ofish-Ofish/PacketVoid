## 🛠️ Dependency Setup: WinDivert

This project relies on the WinDivert kernel-mode packet filter to intercept and modify network traffic. To keep this repository lightweight and free of binary blobs, the pre-compiled library files are not tracked in version control. 

You must manually download and link the WinDivert library before compiling this project in Visual Studio.

### Step 1: Download the Binaries
1. Navigate to the official WinDivert releases page: [https://github.com/basil00/WinDivert/releases](https://github.com/basil00/WinDivert/releases)
2. Expand the **Assets** dropdown for the latest stable release (e.g., version 2.2.2).
3. Download the pre-compiled binary archive. **Important:** Download the file ending in `-A.zip` (e.g., `WinDivert-2.2.2-A.zip`). Do *not* download the Source Code zip.

### Step 2: Organize the Project Directory
1. Inside the root of this repository (where the `.vcxproj` file is located), create a new folder named `vendor`.
2. Extract the contents of the downloaded `.zip` file into this `vendor` directory. 
3. Verify your folder structure looks like this:
   ```text
   PacketVoid/
   ├── Program/
   │   ├── vendor/
   │   │   ├── WinDivert-2.2.2/
   │   │   │   ├── include/       (Contains windivert.h)
   │   │   │   ├── x64/           (Contains WinDivert.lib, .dll, and .sys)
   │   │   │   └── x86/
   │   ├── main.c
   │   └── injectorEngine.c