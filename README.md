# FM5 Split-Screen & Multiplayer Fix (PC / Azimuth 1.0.4)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows / Linux (Proton)](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20(Proton)-green.svg)](#installation)
[![Game: Forza Motorsport 5](https://img.shields.io/badge/Game-Forza%20Motorsport%205-red.svg)](#)

A standalone runtime fix and `dinput8.dll` proxy enabling **full, stable 2-Player Split-Screen multiplayer** in *Forza Motorsport 5* (Xbox One Durango) running on PC via the [Azimuth 1.0.4](https://almost-there-games.itch.io/azimuth) translation layer (both on native Windows and Linux via Proton/Wine).

---

## The Breakthrough

Historically, running *Forza Motorsport 5* in Split-Screen mode on PC was completely broken due to architectural limitations in the translation layer and memory bugs in the console engine when handling multiple viewports:

1. **Player 2 Sign-In Lockout:** Azimuth hardcodes a single static `User` in memory (`0x14084f378` / "Player 1") and stubs console account picker screens with an immediate return of Player 1. When Controller 2 attempts to join the split-screen lobby, the game detects duplicate user objects and rejects the second player.
2. **Race Loading Crash (`0x140687f4c`):** At the transition from the split-screen car selection lobby to the 3D track, an unhandled window activation state causes a NULL pointer dereference in the game's event queue iterator, crashing the game before the track renders.
3. **Runaway Backward Copy in Visibility Thread (`0x1408595e0`):** In split-screen, the combined geometry of Player 1, Player 2, and four active rear-view mirrors saturates the global visibility vector (`0x1424717d0`). When the engine pops the worst element and inserts the new candidate at the end of the list, an unsigned conditional jump (`JAE`) in `vector::insert` treats the negative count as a massive unsigned integer (~`0xFFFFFFFFFFFFFFF5`), triggering an infinite backward copy loop that overwrites ~1 MB of title memory and collapses 4 threads with `EXCEPTION_ACCESS_VIOLATION`.
4. **Runaway Forward Scan in Visibility Helper (`0x14085b770`):** Once past the starting grid, vehicle acceleration queues additional meshes. A binary search placement beyond `_Mylast` feeds `where = _Mylast + 0x10` into helper `0x14085b770`. The helper's equality check (`JE`) fails, causing a forward memory scan that runs off the page boundary at `0x40000360000`.

**This fix resolves all four failure modes completely, enabling seamless split-screen multiplayer gameplay across full races.**

---

## Technical Architecture

The fix is compiled into a high-performance, zero-latency `dinput8.dll` proxy that dynamically attaches to the process:

### 1. WinRT Identity & COM Controller Pairing Emulation
- **Dynamic Multi-User Pool:** Dynamically manages separate `User` instances for Player 1 (native) and Player 2 (virtual guest), hook-intercepting:
  - `Windows.Xbox.Input.Controller::get_User` (`0x19a4c0`)
  - `Windows.Xbox.System.UserStatics::get_Users` (`0x424a0`)
  - `UserStatics::GetUserById` (`0x42580`)
  - `UserDisplayInfo::get_DisplayName` (`0x41d10`)
  - `UserStatics` vtable slots 6 (`0x42480`), 7 (`0x425c0`), and 8 (`0x425e0`)
- **Synthesized COM `IControllerPairingChangedEventArgs`:** Synthesizes the full 13-slot vtable COM pairing args with strict `QueryInterface` and `AddRef` ownership semantics, firing `ControllerPairingChanged` events as gamepads are designated to P1 or P2.
- **Button Remapping:** Fixes Azimuth's DirectInput bitshift defect that zeroes out `GamepadButtons::Menu` (Start) and `GamepadButtons::View` (Back).

### 2. Race Transition & Event Shield
- **`WindowActivated` Handler (RVA `0x5d7500`):** Forces `S_OK` return on window activation state changes during scene transitions.
- **Queue Guard (RVA `0x687f48`–`0x687f4f`):** Installs an atomic code cave guarding the event iterator against NULL heads.

### 3. Four-Layer Visibility Thread Shield
- **Layer 1 (RVA `0x859516`):** Atomic 16-bit store replacing unsigned `JAE` (`0F 83`) with signed `JGE` (`0F 8D`). When `where >= _Mylast` (count is negative), the backward copy loop branch is bypassed directly to the clean end-append path (`0x85951c`).
- **Layer 2 (RVA `0x859500`):** Aligned 64-bit jump cave trapping `where > _Mylast` and simultaneously clamping `%r8`, `%rax` (`count = 0`), `%rbp`, and stack spill `[rsp+0x90]`.
- **Layer 3 (RVA `0x85B773`):** Patches helper `0x14085b770` from `JE` (`74 26`) to `JAE` (`73 26`), immediately returning in 0 cycles if `rcx >= rdx`.
- **Layer 4 (RVA `0x8580E0`):** Pre-insertion cave at binary search exit comparing candidate `%r8` directly with global `_Mylast` (`0x1424717D8`).

---

## Installation

### Easy Install (Pre-compiled Binary)

1. Download `dinput8.dll` from the latest [Releases](https://github.com/maiteuxzanela/fm5-splitscreen-fix/releases).
2. Place `dinput8.dll` in your Forza Motorsport 5 root folder (the folder containing `azimuth.exe`).
3. **Linux / Steam Deck / Proton Users:**
   Ensure Wine loads the local proxy by setting:
   ```bash
   WINEDLLOVERRIDES="dinput8=n,b" %command%
   ```
   *(Or run through your custom shell launcher with `WINEDLLOVERRIDES="dinput8=n,b"` exported).*

---

## How to Play Split-Screen

1. Connect two controllers (Xbox, DualShock, DualSense, or DirectInput gamepads).
2. Launch the game.
3. At the title screen, press **A** on Controller 1 to claim the Player 1 profile.
4. Navigate to **Multiplayer** $\rightarrow$ **Split-Screen**.
5. In the lobby, press **Start / Menu** on Controller 2 to sign in as Player 2.
6. Choose cars, select the track, and confirm the race.
7. Enjoy smooth split-screen racing on PC!

---

## Building from Source

### Prerequisites
- Linux: `gcc`, `make`, `python3` (for test suite)
- Cross-compilation to Windows: `x86_64-w64-mingw32-gcc` OR `zig` (via `zig cc`)

### Build Commands

```bash
# Clone the repository
git clone https://github.com/maiteuxzanela/fm5-splitscreen-fix.git
cd fm5-splitscreen-fix

# Run deterministic native test suite (100% real execution, zero mocks)
make test

# Compile dist/dinput8.dll
make dll
```

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.  
All reverse engineering and hook implementations are 100% clean-room C/Assembly and do not distribute any copyrighted game or emulator assets.

---

## Credits & Acknowledgements

- **Maiteux Zanela** — Reverse engineering, root-cause diagnosis, hook architecture, and full in-game split-screen field validation.
- **OpenCode Harness Team** — Deterministic test engineering, mutation sensitivity testbed, and systems architecture.
- **Almost There Games** — Creators of the [Azimuth](https://almost-there-games.itch.io/azimuth) translation layer.
