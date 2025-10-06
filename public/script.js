

    const player = new shaka.Player(document.getElementById('video'));
    const video = document.getElementById('video');
    const playPauseBtn = document.getElementById('playPauseBtn');
    const volumeIcon = document.getElementById('volumeIcon');
    const volumeSvg = document.getElementById('volumeSvg');
    const fullscreenBtn = document.getElementById('fullscreenBtn');
    const seekBar = document.getElementById('seekBar');
    const pipBtn = document.getElementById('pipToggle');
    const dropdown = document.getElementById('settingsDropdown');
    const volumeBtn = document.querySelector('#volumeIcon'); // The button element only
    const volumeSlider = document.getElementById('volumeSlider');
    const controls = document.getElementById('videoControls');   // your controls div
    const container = document.getElementById('videoContainer'); // wrapper
    const qualityOptionsTrigger = document.querySelector('#qualityOptions > div');
    // Get the video container and button elements
    const theaterBtn = document.getElementById('theaterBtn');
    const body = document.body; // Or any other container element

// Function to toggle theater mode
theaterBtn.addEventListener('click', () => {
  // Toggle the "theater-mode" class on the body
  body.classList.toggle('theater-mode');
  
  // Change the button text to "Exit Theater Mode" or back to "Theater Mode"
  if (body.classList.contains('theater-mode')) {
    theaterBtn.textContent = "Exit Theater Mode 🎭";
  } else {
    theaterBtn.textContent = "Theater Mode 🎭";
  }

  // If we are in Theater Mode, let's make the video controls more accessible
  const videoPlayer = document.getElementById('videoPlayer');
  if (body.classList.contains('theater-mode')) {
    videoPlayer.controls = true;  // Enable controls when in Theater Mode
  } else {
    videoPlayer.controls = false; // Hide controls when not in Theater Mode
  }
});

 

    volumeSlider.value = video.volume;
    let dropdownVisible = false;
    
    


  

let hideControlsTimeout;

function showControls() {
  controls.classList.remove('hidden');
  resetHideTimeout();
}

function hideControls() {
  controls.classList.add('hidden');
}

function resetHideTimeout() {
  clearTimeout(hideControlsTimeout);
  hideControlsTimeout = setTimeout(() => {
    if (!video.paused) {
      hideControls();
    }
  }, 3000); // Hide after 3 seconds
}

// Show controls on mouse move
container.addEventListener('mousemove', showControls);

// Show controls again on play
video.addEventListener('play', () => {
  showControls();
  resetHideTimeout();
});

// Keep hidden on pause (or always show, if desired)
video.addEventListener('pause', () => {
  showControls(); // Or use hideControls() if you want to hide always
});

// Also reset timer on touch for mobile
container.addEventListener('touchstart', showControls);



function setBodyHeight() {
  // Use innerHeight to get visible area excluding browser bars
  document.body.style.minHeight = window.innerHeight + 'px';
}

// Initial set
setBodyHeight();

// Update on resize / orientation change
window.addEventListener('resize', setBodyHeight);
window.addEventListener('orientationchange', setBodyHeight);

function setMediumBodyHeight() {
  // Medium height: 1.5x visible viewport
  document.body.style.minHeight = (window.innerHeight * 1.5) + 'px';
}

// Initial call
setMediumBodyHeight();

// Update on resize/orientation change
window.addEventListener('resize', setMediumBodyHeight);
window.addEventListener('orientationchange', setMediumBodyHeight);




// ==== Ultimate IPTV Streaming Manager (Full Integrated) ====

// --- Global state & constants ---
let shakaPlayer = null;
let currentHls = null;
let videoElement = null;
let channelList = []; // populate your channels here
let retryCount = 0;
const maxRetries = 12;
let lastBandwidthEstimate = 10;
let lastQualityChange = 0;
const qualityChangeCooldown = 3500;
let lowPowerMode = false;
let bandwidthSamples = [];

// Device & network info
const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
const deviceMemory = navigator.deviceMemory || 4;
const saveData = connection?.saveData || false;
const userAgent = navigator.userAgent;

function isMobileDevice() { return /Mobi|Android/i.test(userAgent); }
function isLowPowerDevice() { return deviceMemory <= 2 || saveData; }
async function getBatteryStatus() { if ('getBattery' in navigator) try { return await navigator.getBattery(); } catch { return null; } return null; }
async function isDeviceOverheating() { const battery = await getBatteryStatus(); if (!battery) return false; return battery.charging && battery.level > 0.6; }
function getCurrentBandwidth() { return connection?.downlink || lastBandwidthEstimate; }

// ===== Utility Functions =====
function isMobileDevice() {
  return /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);
}
function isTablet() {
  return Math.min(window.screen.width, window.screen.height) >= 768;
}

const videoContainer = document.getElementById('videoContainer');
const videoEl = videoContainer.querySelector('video');


async function toggleFullscreen() {
  try {
    const isFullscreen = !!document.fullscreenElement;

    if (!isFullscreen) {
      // Enter fullscreen
      if (videoContainer.requestFullscreen) {
        await videoContainer.requestFullscreen({ navigationUI: 'hide' });
      } else if (videoEl.webkitEnterFullscreen) {
        // iOS fallback for Safari
        videoEl.webkitEnterFullscreen();
        return;
      }

      // Force recalculation of viewport height for Android browsers
      adjustViewportHeight();

      // Lock orientation if supported
      if (screen.orientation?.lock) {
        try {
          await screen.orientation.lock('landscape');
        } catch (e) {
          console.warn('Orientation lock failed:', e);
        }
      }

      videoContainer.classList.add('portrait-mode');
    } else {
      // Exit fullscreen
      if (document.exitFullscreen) {
        await document.exitFullscreen();
      }

      if (screen.orientation?.unlock) {
        screen.orientation.unlock();
      }

      videoContainer.classList.remove('portrait-mode');
      resetViewportHeight();
    }
  } catch (err) {
    console.error('Fullscreen toggle error:', err);
  }
}

document.addEventListener('fullscreenchange', () => {
  if (!document.fullscreenElement) {
    resetViewportHeight();
    videoContainer.classList.remove('portrait-mode');
  }
});

fullscreenBtn.addEventListener('click', toggleFullscreen);

// === Helpers ===
function adjustViewportHeight() {
  const vh = window.innerHeight * 0.01;
  document.documentElement.style.setProperty('--vh', `${vh}px`);
  videoContainer.style.height = `calc(var(--vh, 1vh) * 100)`;
}

function resetViewportHeight() {
  document.documentElement.style.removeProperty('--vh');
  videoContainer.style.height = '';
}
function setMediumPageHeight() {
  // Get visible viewport height
  const vh = window.innerHeight;

  // Medium height: 1.2x to 1.3x viewport for a “medium” scrollable page
  document.body.style.minHeight = (vh * 1.25) + 'px';
}

// Initial set
setMediumPageHeight();

// Update dynamically on resize / orientation change
window.addEventListener('resize', setMediumPageHeight);
window.addEventListener('orientationchange', setMediumPageHeight);



  class UltraSuperSonicIPTVEngineOptimized {
    constructor(channels, videoEl, opts = {}) {
        if (!videoEl) throw new Error("Video element required");
        this.video = videoEl;
        this._monitoringRAF = null;
        this._resizeObserver = new ResizeObserver(() => this._resizeCanvas());
        this._resizeObserver.observe(this.video);

        // ---------- NEW: Device capability detection ----------
        this.deviceMemory = navigator.deviceMemory || 4; // GB estimate fallback
        this.cpuCores = navigator.hardwareConcurrency || 2;
        this.isLowEnd = (this.deviceMemory <= 2 || this.cpuCores <= 2);

        // ---------- Core flags & tuning ----------
        this._maxConcurrentPreloads = opts.maxConcurrentPreloads || 12;
        this.parallelStreams = opts.parallelStreams || 16;
        this.qualityBlendLevels = opts.qualityBlendLevels || 8;
        this.superSonicMode = opts.superSonicMode !== false;
        this.turboMode = opts.turboMode !== false;

        // ---------- Infinite-buffer & safety options ----------
        this.config = Object.assign({
            PRELOAD_LIMIT: opts.PRELOAD_LIMIT || 50,
            BUFFER_HEALTH_THRESHOLD: opts.BUFFER_HEALTH_THRESHOLD || 2,
            HEAL_INTERVAL: opts.HEAL_INTERVAL || 25,
            MAX_PRELOAD_CACHE: opts.MAX_PRELOAD_CACHE || 120,
            PRELOAD_ON_ZAP: opts.PRELOAD_ON_ZAP !== false,
            AUTO_QUALITY_ADJUST: opts.AUTO_QUALITY_ADJUST !== false,
            FAILOVER_MAX_ATTEMPTS: opts.FAILOVER_MAX_ATTEMPTS || 5,
            MULTI_QUALITY_PRELOAD: opts.MULTI_QUALITY_PRELOAD !== false,
            MAX_PRELOAD_QUALITIES_PER_CHANNEL: opts.MAX_PRELOAD_QUALITIES_PER_CHANNEL || 3,
            // NEW:
            INFINITY_BUFFER_ENABLED: !!opts.INFINITY_BUFFER_ENABLED,
            INFINITY_MAX_SECONDS: opts.INFINITY_MAX_SECONDS || (this.isLowEnd ? 120 : 1200), // target buffer seconds
            INFINITY_DATA_BUDGET_BYTES: opts.INFINITY_DATA_BUDGET_BYTES || (this.isLowEnd ? 50 * 1024 * 1024 : 400 * 1024 * 1024), // 50MB low-end, 400MB otherwise
            INFINITY_LOWBITRATE_PREFERENCE: opts.INFINITY_LOWBITRATE_PREFERENCE !== false,
            THROUGHPUT_EPMA_ALPHA: 0.2, // EWMA alpha for throughput estimator
            THROUGHPUT_SAMPLE_BYTES: 64 * 1024 // fetch first 64KB to estimate
        }, opts);

        this.channels = (channels || []).map(ch => {
            if (!ch.url && !ch.qualities) ch.qualities = { '480p': [] };
            else if (ch.url && !ch.qualities) ch.qualities = { '480p': [ch.url] };
            return ch;
        });

        // ---------- runtime state ----------
        this.currentIndex = 0;
        this.bufferHealth = 0;
        this._blendedVideos = [];
        this._freezePredictor = null;
        this._destroyed = false;

        this.preloadCache = new Map(); // key -> {els: [video], lastUsedAt, totalBytes}
        this.failedServers = new Map();
        this._failoverAttempts = new Map();
        this.userHistory = JSON.parse(localStorage.getItem('zapHistory') || '[]');

        // throughput estimator (bytes/sec) - EWMA
        this.throughputEWMA = null;

        this._initOverlay();
        this._setupFailover();

        if (this.superSonicMode) this.enableSuperSonicMode();
        this._startMonitoring();

        if (this.channels.length > 0) this.playChannelSafe(0);
        window.addEventListener('resize', () => this._resizeCanvas());

        // periodic maintenance
        setInterval(() => { if (!this._destroyed) this._ensurePreloadLimit(); }, 5 * 60 * 1000);

        // Aggressive infinite-buffer fill if configured
        if (this.config.INFINITY_BUFFER_ENABLED) {
            // attempt to start a measured fill
            this._attemptInfinityBufferFill().catch(()=>{});
        }
    }

    // ---------------- SuperSonic + Turbo Adaptive ----------------
    enableSuperSonicMode() {
        if (this._freezePredictor) return;
        console.log("⚡ Ultra Super Sonic Mode Activated");
        this._freezePredictor = setInterval(() => {
            if (!this.video) return;
            // auto-detect heavy streams and react
            this._detectHeavyStreamAndReact();
            if (this.bufferHealth < this.config.BUFFER_HEALTH_THRESHOLD + 5) this._autoQualitySwitch();
            this._predictivePreloadNextChannels();
            this._blendStreamsAdaptive();
        }, Math.max(15, this.config.HEAL_INTERVAL));
        this._initCanvasPiP();
    }

    disableSuperSonicMode() {
        if (!this._freezePredictor) return;
        clearInterval(this._freezePredictor);
        this._freezePredictor = null;
        console.log("🛑 Ultra Super Sonic Mode Deactivated");
    }

    // ----------------- NEW: Heavy-stream detection & reaction -----------------
    async _measureThroughputProbe(url) {
        // Try to GET a small range to estimate throughput. Servers might not allow it; handle gracefully.
        try {
            const controller = new AbortController();
            const rangeBytes = this.config.THROUGHPUT_SAMPLE_BYTES;
            const headers = { Range: `bytes=0-${rangeBytes - 1}` };
            const t0 = performance.now();
            const res = await fetch(url, { headers, signal: controller.signal, cache: "no-store" });
            if (!res.ok || !res.body) return null;
            // read stream to measure actual bytes
            const reader = res.body.getReader();
            let total = 0;
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                total += value.byteLength;
                if (total >= rangeBytes) break;
            }
            const t1 = performance.now();
            const seconds = Math.max((t1 - t0) / 1000, 0.001);
            return total / seconds; // bytes/sec
        } catch (e) {
            return null;
        }
    }

    _updateThroughputEstimate(sample) {
        if (!sample || sample <= 0) return;
        if (!this.throughputEWMA) this.throughputEWMA = sample;
        else this.throughputEWMA = this.config.THROUGHPUT_EPMA_ALPHA * sample + (1 - this.config.THROUGHPUT_EPMA_ALPHA) * this.throughputEWMA;
    }

    async _detectHeavyStreamAndReact() {
        // Gather metrics
        try {
            const quality = this.video.getVideoPlaybackQuality ? this.video.getVideoPlaybackQuality() : null;
            const dropped = quality ? (quality.droppedVideoFrames || 0) : (this.video.webkitDroppedFrameCount || 0);
            // Buffer health is already tracked by monitor
            const buffer = this.bufferHealth || 0;

            // Sample throughput from current stream (non-blocking if already running)
            if (!this._throughputProbeRunning && this.video.currentSrc) {
                this._throughputProbeRunning = true;
                this._measureThroughputProbe(this.video.currentSrc).then(sample => {
                    if (sample) this._updateThroughputEstimate(sample);
                }).finally(() => { this._throughputProbeRunning = false; });
            }

            // Heuristics
            const lowThroughput = this.throughputEWMA ? (this.throughputEWMA < (200 * 1024)) : false; // <200kb/s indicates problem
            const lotsDropped = dropped && dropped > 5;
            const lowBuffer = buffer < Math.max(1, this.config.BUFFER_HEALTH_THRESHOLD);

            // If we detect 'heavy stream' symptoms, react:
            if (lowThroughput || lotsDropped || lowBuffer) {
                // Throttle heavy visual work
                if (this.isLowEnd || lowThroughput) {
                    this._reduceVisualWorkForLowEnd();
                }
                // Force quality down to the nearest low-bitrate
                this._forceLowerQualityForStability();
                // Try to extend buffer using low-bitrate preloads if infinity enabled or allowed
                if (this.config.INFINITY_BUFFER_ENABLED) {
                    this._attemptInfinityBufferFill().catch(()=>{});
                } else {
                    // increase preloads for low bitrate variants temporarily
                    this._preloadLowBitratesForCurrentChannel(Math.min(6, this._maxConcurrentPreloads));
                }
            } else {
                // healthy - if we previously reduced visuals, restore blended behavior
                if (!this.isLowEnd) this._maybeRestoreVisuals();
            }
        } catch (e) { /* defensive */ }
    }

    _reduceVisualWorkForLowEnd() {
        // Reduce blending, stop canvas draws, etc.
        try {
            if (this._canvas) {
                // Lower update frequency by swapping to interval draw or hiding canvas
                if (!this._lowPowerCanvas) {
                    this._lowPowerCanvas = true;
                    this._ctx && (this._ctx.globalAlpha = 1);
                    // hide canvas to avoid expensive drawImage if truly low-end
                    this._canvas.style.visibility = 'hidden';
                    console.log("🔧 Reduced visual work for low-end device");
                }
            }
            // Stop creating many blended videos
            this.qualityBlendLevels = Math.max(1, Math.min(this.qualityBlendLevels, 2));
            this.parallelStreams = Math.max(1, Math.min(this.parallelStreams, 3));
        } catch { }
    }

    _maybeRestoreVisuals() {
        try {
            if (this._canvas && this._lowPowerCanvas) {
                this._lowPowerCanvas = false;
                this._canvas.style.visibility = 'visible';
                console.log("🔧 Restored visuals after stable conditions");
            }
            // restore some defaults if turbo allowed
            this.qualityBlendLevels = Math.min(this.qualityBlendLevels, 8);
            this.parallelStreams = Math.max(this.parallelStreams, 4);
        } catch { }
    }

    _forceLowerQualityForStability() {
        try {
            const ch = this.channels[this.currentIndex];
            if (!ch) return;
            const quals = this.chooseQualities(ch);
            if (!quals.length) return;
            const lowest = quals[quals.length - 1];
            const currentQuality = this._currentForcedQuality;
            if (currentQuality !== lowest) {
                console.log(`⬇️ Forcing lower quality (${lowest}) for stability`);
                this._currentForcedQuality = lowest;
                const cached = this._getCachedUrlFor(this.currentIndex, lowest);
                if (cached && this.video.src !== cached) { this.video.src = cached; this._safePlay(); }
                else {
                    const urls = this.getBestStreams(ch, lowest);
                    if (urls.length && this.video.src !== urls[0]) { this.video.src = urls[0]; this._safePlay(); }
                }
            }
        } catch { }
    }

    // ----------------- NEW: Infinity buffer fill (best effort) -----------------
    async _attemptInfinityBufferFill() {
        if (this._infinityFilling) return;
        if (!this.config.INFINITY_BUFFER_ENABLED) return;
        this._infinityFilling = true;
        try {
            const ch = this.channels[this.currentIndex];
            if (!ch) return;
            // choose low-bitrate qualities preferentially
            const quals = this.chooseQualities(ch).slice().reverse(); // low->high
            let bytesUsed = this._calculatePreloadedBytesForChannel(this.currentIndex);
            const budget = this.config.INFINITY_DATA_BUDGET_BYTES;
            const targetSeconds = this.config.INFINITY_MAX_SECONDS;

            for (const q of quals) {
                if (bytesUsed >= budget) break;
                const urls = this.getBestStreams(ch, q);
                if (!urls || !urls.length) continue;
                // precreate many hidden video preloaders of low bitrate to accumulate buffer seconds
                // but cap concurrency & memory based on device
                const concurrency = Math.max(1, Math.min(6, Math.floor((this.deviceMemory || 2) * 1.5)));
                for (let i = 0; i < concurrency && bytesUsed < budget; i++) {
                    // If we already have a ready cached element for this quality, skip new creation
                    const key = this._makePreloadKey(this.currentIndex, q);
                    if (this.preloadCache.has(key) && this.preloadCache.get(key).els && this.preloadCache.get(key).els[0] && this.preloadCache.get(key).els[0].readyState >= 2) {
                        // already cached
                        break;
                    }
                    // create preload - this avoids re-downloading if same URL used
                    try {
                        await this._createPreloadForAsync(this.currentIndex, q, urls[0]);
                        bytesUsed = this._calculatePreloadedBytesForChannel(this.currentIndex);
                    } catch (e) { break; }
                }
                // heuristically stop once we think we have enough buffer seconds
                const approxSec = this._approximateBufferedSecondsForChannel(this.currentIndex);
                if (approxSec >= targetSeconds) break;
            }
            console.log("♾️ Infinity fill attempt complete (best-effort)", { bytesUsed, budget });
        } catch (e) { console.warn("Infinity fill failed:", e); }
        this._infinityFilling = false;
    }

    _calculatePreloadedBytesForChannel(idx) {
        let total = 0;
        for (const [k, v] of this.preloadCache.entries()) {
            if (!k.startsWith(`ch${idx}_`)) continue;
            total += (v.totalBytes || 0);
        }
        return total;
    }

    _approximateBufferedSecondsForChannel(idx) {
        // crude estimate: bufferedSeconds = totalBytes / throughput
        const bytes = this._calculatePreloadedBytesForChannel(idx);
        const throughput = Math.max(1, (this.throughputEWMA || (300 * 1024))); // bytes/sec
        return Math.floor(bytes / throughput);
    }

    _createPreloadFor(idx, quality, url) {
        // keep backward-compat synchronous interface: schedule creation
        setTimeout(() => this._createPreloadForAsync(idx, quality, url).catch(()=>{}), 0);
    }

    async _createPreloadForAsync(idx, quality, url) {
        if (this._destroyed) return;
        const key = this._makePreloadKey(idx, quality);
        if (this.preloadCache.has(key)) { this.preloadCache.get(key).lastUsedAt = Date.now(); return; }
        const v = document.createElement('video');
        v.src = url;
        v.muted = true; v.playsInline = true; v.preload = 'auto';
        v.style.display = 'none';
        // To estimate size, attempt to fetch small portion of stream to measure bytes
        let totalBytes = 0;
        try {
            // append to body then try to start load
            document.body.appendChild(v);
            // try to play briefly to encourage browser to load; browsers may limit autoplay
            v.play().catch(()=>{});
            // when metadata available, try to read network info via Resource Timing if possible
            v.addEventListener('loadeddata', () => { /* no-op */ }, { once: true });
            // we keep the video element as preload cache
        } catch (e) { }
        this.preloadCache.set(key, { els: [v], lastUsedAt: Date.now(), totalBytes });
        this._ensurePreloadLimit();
    }

    _preloadLowBitratesForCurrentChannel(count = 6) {
        const ch = this.channels[this.currentIndex];
        if (!ch) return;
        const quals = this.chooseQualities(ch).slice().reverse(); // low->high
        let c = 0;
        for (const q of quals) {
            if (c >= count) break;
            const urls = this.getBestStreams(ch, q);
            if (!urls.length) continue;
            this._createPreloadFor(this.currentIndex, q, urls[0]);
            c++;
        }
    }

    // ---------------- Blend / PiP improvements (optimize for low-end) ----------------
    _blendStreamsAdaptive() {
        if (!this._canvas || !this._blendedVideos.length) return;
        const buffer = this.bufferHealth;
        // fewer streams for low end or low buffer
        const maxStreams = Math.min(
            this._blendedVideos.length,
            Math.max(1, Math.round(buffer / 3)),
            this.isLowEnd ? 1 : Math.max(1, Math.round(this.deviceMemory / 2))
        );
        const activeVideos = this._blendedVideos.slice(0, maxStreams);

        const ctx = this._ctx;
        const canvas = this._canvas;

        // if low-power canvas mode, avoid continuous draw loop
        if (this._lowPowerCanvas) {
            // keep canvas hidden and ensure videos are not playing unnecessarily
            activeVideos.forEach(v => { try { v.pause(); } catch {} });
            return;
        }

        if (this._canvasDrawLoopRunning) return;
        this._canvasDrawLoopRunning = true;
        const drawLoop = () => {
            if (this._destroyed) { this._canvasDrawLoopRunning = false; return; }
            try {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                const readyVideos = activeVideos.filter(v => v && v.readyState >= 2);
                if (!readyVideos.length) { requestAnimationFrame(drawLoop); return; }
                const alpha = 1 / readyVideos.length;
                readyVideos.forEach(v => { ctx.globalAlpha = alpha; try { ctx.drawImage(v, 0, 0, canvas.width, canvas.height); } catch { } });
            } catch { }
            // choose RAF frequency depending on device
            if (this.isLowEnd) setTimeout(() => requestAnimationFrame(drawLoop), 200); // slow down for low-end
            else requestAnimationFrame(drawLoop);
        };
        drawLoop();
    }

    // ---------------- Overlay ----------------
  _initOverlay() {
    try {
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: absolute;
            top: 1px;
            right: 8px;
            font-size: 10px;
            padding: 6px 10px;
            z-index: 9999;
            font-family: monospace;
            background: transparent;
            border-radius: 6px;
            display: flex;
            align-items: center;
            pointer-events: none; /* overlay won’t block clicks */
        `;

        // Static label
        const label = document.createElement('span');
        label.textContent = 'Buffer:';
        overlay.appendChild(label);

        // Number span that will change color
        const number = document.createElement('span');
        number.textContent = '0s';
        number.style.transition = 'color 0.15s linear'; // smooth, lightweight transition
        overlay.appendChild(number);
        this._overlayNumber = number;

        // Append overlay to video parent or body
        const parent = this.video.parentElement || document.body;
        if (window.getComputedStyle(parent).position === 'static') parent.style.position = 'relative';
        parent.appendChild(overlay);
    } catch (e) {
        console.error("Overlay init failed:", e);
    }
}

_updateOverlay() {
    if (!this._overlayNumber) return;

    const bufferSec = Math.round(this.bufferHealth);
    this._overlayNumber.textContent = `${bufferSec}s`;

    // Normalize buffer for color (0s = red, maxBuffer = green)
    const maxBuffer = 10; // fully green at 20s
    let t = Math.min(bufferSec / maxBuffer, 1); // 0 → 1

    // Red (0°) → Yellow (60°) → Green (120°)
    const hue = t * 120;
    this._overlayNumber.style.color = `hsl(${hue}, 100%, 50%)`;
}

_startMonitoring() {
    if (this._monitoringRAF) return;

    const loop = () => {
        if (this._destroyed) return;

        try {
            const buffered = this.video.buffered;
            this.bufferHealth = buffered.length
                ? buffered.end(buffered.length - 1) - this.video.currentTime
                : 0;
        } catch {
            this.bufferHealth = 0;
        }

        this._updateOverlay();
        this._monitoringRAF = requestAnimationFrame(loop);
    };

    loop();
}

_destroyOverlay() {
    if (this._monitoringRAF) cancelAnimationFrame(this._monitoringRAF);
    this._monitoringRAF = null;
    if (this._overlayNumber && this._overlayNumber.parentElement) {
        this._overlayNumber.parentElement.remove();
    }
    this._overlayNumber = null;
}





    // ---------------- Channel & Preload Helpers ----------------
    chooseQualities(channel) {
        if (!channel) return ['480p'];
        return Object.keys(channel.qualities || {}).sort((a, b) => (parseInt(b) || 0) - (parseInt(a) || 0)).slice(0, this.qualityBlendLevels);
    }

    getBestStreams(channel, quality) {
        const urls = (channel && channel.qualities?.[quality]) ? channel.qualities[quality] : (channel && channel.url ? [channel.url] : []);
        return urls.filter(u => !this.failedServers.get(u) || (Date.now() - this.failedServers.get(u) > this.config.HEAL_INTERVAL)).slice(0, this.parallelStreams);
    }

    markServerFailed(url) { try { this.failedServers.set(url, Date.now()); } catch { } }

    recordHistory(idx) {
        try { this.userHistory.push({ index: idx, time: Date.now() }); if (this.userHistory.length > 5000) this.userHistory.shift(); localStorage.setItem('zapHistory', JSON.stringify(this.userHistory)); } catch { }
    }

    _makePreloadKey(idx, quality) { return `ch${idx}_${quality}`; }

    _ensurePreloadLimit() {
        if (this.preloadCache.size <= this.config.MAX_PRELOAD_CACHE) return;
        const arr = Array.from(this.preloadCache.entries()).sort((a, b) => a[1].lastUsedAt - b[1].lastUsedAt);
        const removeCount = this.preloadCache.size - this.config.MAX_PRELOAD_CACHE;
        for (let i = 0; i < removeCount; i++) { const entry = arr[i][1]; try { (entry.els || []).forEach(v => { try { v.pause(); v.remove(); } catch { } }); } catch { } this.preloadCache.delete(arr[i][0]); }
    }

    _createPreloadFor(idx, quality, url) {
        if (this._destroyed) return;
        const key = this._makePreloadKey(idx, quality);
        if (this.preloadCache.has(key)) { this.preloadCache.get(key).lastUsedAt = Date.now(); return; }
        const v = document.createElement('video'); v.src = url; v.muted = true; v.playsInline = true; v.preload = 'auto'; v.style.display = 'none';
        document.body.appendChild(v); v.play().catch(() => { });
        this.preloadCache.set(key, { els: [v], lastUsedAt: Date.now() });
        this._ensurePreloadLimit();
    }

    _preloadQualitiesForChannel(idx) {
        if (this._destroyed || !this.config.PRELOAD_ON_ZAP) return;
        const ch = this.channels[idx]; if (!ch) return;
        let bufferFactor = Math.min(Math.max(this.bufferHealth / 10, 0.3), 1);
        const maxQualities = Math.ceil(this.config.MAX_PRELOAD_QUALITIES_PER_CHANNEL * bufferFactor);
        const quals = this.chooseQualities(ch).slice(0, maxQualities);
        quals.forEach(q => { const urls = this.getBestStreams(ch, q); if (!urls.length) return; setTimeout(() => this._createPreloadFor(idx, q, urls[0]), 0); });
    }

    _predictivePreloadNextChannels() {
        if (!this.config.PRELOAD_ON_ZAP || !this.channels || !this.channels.length) return;
        const nextSet = new Set();
        try {
            const recent = this.userHistory.slice(-200);
            const freq = {};
            recent.forEach(h => freq[h.index] = (freq[h.index] || 0) + 1);
            Object.keys(freq).map(Number).sort((a, b) => freq[b] - freq[a]).slice(0, Math.min(10, this._maxConcurrentPreloads)).forEach(idx => nextSet.add(idx));
        } catch { }
        for (let i = 1; i <= this._maxConcurrentPreloads; i++) nextSet.add((this.currentIndex + i) % this.channels.length);
        nextSet.forEach(idx => this._preloadQualitiesForChannel(idx));
    }

    _getCachedUrlFor(idx, quality) {
        if (quality) { const key = this._makePreloadKey(idx, quality); const entry = this.preloadCache.get(key); if (entry && Array.isArray(entry.els) && entry.els[0] && entry.els[0].readyState >= 2) { entry.lastUsedAt = Date.now(); return entry.els[0].src; } }
        const ch = this.channels[idx]; if (!ch) return null;
        const quals = this.chooseQualities(ch);
        for (const q of quals) { const e = this.preloadCache.get(this._makePreloadKey(idx, q)); if (e && Array.isArray(e.els) && e.els[0] && e.els[0].readyState >= 2) { e.lastUsedAt = Date.now(); return e.els[0].src; } }
        return null;
    }

    async _safePlay() { try { await this.video.play(); } catch { } }

    async seamlessZap(index) {
        if (!this.channels[index]) index = 0;
        this.currentIndex = index;
        const ch = this.channels[index]; if (!ch) return;
        const quals = this.chooseQualities(ch); const preferredQuality = this._currentForcedQuality || quals[0];
        const cachedUrl = this._getCachedUrlFor(index, preferredQuality);
        if (cachedUrl) { this.video.src = cachedUrl; await this._safePlay(); this.recordHistory(index); this._predictivePreloadNextChannels(); return; }
        const fallbackUrl = (ch.url ? [ch.url] : [])[0] || (this.getBestStreams(ch, preferredQuality)[0]); if (!fallbackUrl) return;
        this.video.src = fallbackUrl; await this._safePlay(); this.recordHistory(index); this._predictivePreloadNextChannels();
    }

    playChannelSafe(index) { this.seamlessZap(index).catch(() => { this.playChannelHighestQuality(index); }); }

    playChannelHighestQuality(index) {
        if (!this.channels[index]) index = 0; this.currentIndex = index;
        this._blendedVideos.forEach(v => { try { v.pause(); v.remove(); } catch { } }); this._blendedVideos = [];
        const ch = this.channels[index]; const quals = this.chooseQualities(ch);
        quals.slice(0, Math.min(4, quals.length)).forEach(q => {
            const urls = this.getBestStreams(ch, q); if (!urls.length) return;
            const v = document.createElement('video'); v.src = urls[0]; v.autoplay = true; v.muted = true; v.playsInline = true; v.preload = 'auto'; v.style.display = 'none';
            document.body.appendChild(v); this._blendedVideos.push(v);
        });
        this._blendStreamsAdaptive(); this._predictivePreloadNextChannels(); this._autoQualitySwitch();
    }

    _autoQualitySwitch() {
        if (this._destroyed || !this.config.AUTO_QUALITY_ADJUST) return;
        const ch = this.channels[this.currentIndex]; if (!ch) return;
        const quals = this.chooseQualities(ch); const buffer = this.bufferHealth;
        let targetQuality = this._currentForcedQuality || quals[0];
        if (buffer < 1 && quals.length > 1) targetQuality = quals[quals.length - 1];
        const cached = this._getCachedUrlFor(this.currentIndex, targetQuality);
        if (cached && this.video.src !== cached) { this.video.src = cached; this._safePlay(); }
        else { const urls = this.getBestStreams(ch, targetQuality); if (urls.length && this.video.src !== urls[0]) { this.video.src = urls[0]; this._safePlay(); } }
        setTimeout(() => this._autoQualitySwitch(), Math.max(10, this.config.HEAL_INTERVAL / 2));
    }

    _setupFailover() {
        this._boundFailoverHandler = async (ev) => {
            if (this._destroyed) return; const currentSrc = this.video.currentSrc || this.video.src; if (!currentSrc) return;
            this.markServerFailed(currentSrc); const attempts = (this._failoverAttempts.get(currentSrc) || 0) + 1; this._failoverAttempts.set(currentSrc, attempts);
            if (attempts > this.config.FAILOVER_MAX_ATTEMPTS) return;
            const ch = this.channels[this.currentIndex]; if (!ch) return;
            const quals = this.chooseQualities(ch).sort(() => Math.random() - 0.5);
            for (let q of quals) {
                const urls = this.getBestStreams(ch, q).sort(() => Math.random() - 0.5);
                for (let u of urls) {
                    if (!u || u === currentSrc) continue;
                    try { this.video.src = u; await this._safePlay(); return; } catch { this.markServerFailed(u); }
                }
            }
        };
        try { this.video.addEventListener('error', this._boundFailoverHandler); this.video.addEventListener('stalled', this._boundFailoverHandler); this.video.addEventListener('suspend', this._boundFailoverHandler); } catch { }
    }

    destroy() {
        this._destroyed = true;
        try { if (this._boundFailoverHandler) { this.video.removeEventListener('error', this._boundFailoverHandler); this.video.removeEventListener('stalled', this._boundFailoverHandler); this.video.removeEventListener('suspend', this._boundFailoverHandler); } } catch { }
        this._blendedVideos.forEach(v => { try { v.pause(); v.remove(); } catch { } }); this._blendedVideos = [];
        try { if (this._canvas) this._canvas.remove(); } catch { }
        for (const entry of this.preloadCache.values()) { try { (entry.els || []).forEach(v => { v.pause(); v.remove(); }); } catch { } }
        this.preloadCache.clear();
        try { if (this._monitoringRAF) cancelAnimationFrame(this._monitoringRAF); } catch { }
        console.log("🛑 Ultra Super Sonic Engine destroyed safely");
    }

    _initCanvasPiP() {
        try { if (this._canvas) this._canvas.remove(); const canvas = document.createElement('canvas'); canvas.width = this.video.clientWidth || 640; canvas.height = this.video.clientHeight || 360; canvas.style.position = 'absolute'; canvas.style.top = '0'; canvas.style.left = '0'; canvas.style.zIndex = 9998; canvas.style.pointerEvents = 'none'; (this.video.parentElement || document.body).appendChild(canvas); this._canvas = canvas; this._ctx = canvas.getContext('2d'); this._resizeCanvas(); } catch { }
    }

    _resizeCanvas() { if (!this._canvas) return; this._canvas.width = this.video.clientWidth || 640; this._canvas.height = this.video.clientHeight || 360; }
}

// ---------------- Loader & Dead-Channel Recovery (unchanged except options) -----------------
document.addEventListener('DOMContentLoaded', async () => {
    const videoEl = document.getElementById('video'); if (!videoEl) return console.error("❌ Video element not found");
    try {
        if (typeof CHANNEL_JSON_URL === 'undefined') throw new Error("❌ CHANNEL_JSON_URL is not defined");
        const res = await fetch(CHANNEL_JSON_URL); if (!res.ok) throw new Error(`❌ Failed to load channels: ${res.status}`);
        const channelList = await res.json(); if (!Array.isArray(channelList) || !channelList.length) { console.error("❌ No channels found in JSON", channelList); return; }
        console.log("✅ Channels loaded:", channelList.map(ch => ch.name || ch.url));
        const engine = new UltraSuperSonicIPTVEngineOptimized(channelList, videoEl, {
            superSonicMode: true, turboMode: true, parallelStreams: 20, qualityBlendLevels: 12,
            AUTO_QUALITY_ADJUST: true, PRELOAD_ON_ZAP: true, HEAL_INTERVAL: 15,
            FAILOVER_MAX_ATTEMPTS: 10, maxConcurrentPreloads: 16, MULTI_QUALITY_PRELOAD: true,
            MAX_PRELOAD_QUALITIES_PER_CHANNEL: 4, MAX_PRELOAD_CACHE: 200,
            INFINITY_BUFFER_ENABLED: true, INFINITY_MAX_SECONDS: 600, INFINITY_DATA_BUDGET_BYTES: 200 * 1024 * 1024
        });
        window.__UltraEngine = engine;

        // Dead-Channel UI
        const msgBox = document.createElement('div');
        msgBox.style.cssText = `position:absolute;bottom:15%;left:50%;transform:translateX(-50%);background:rgba(0,0,0,0.7);color:#ff5555;font-size:16px;padding:10px 18px;border-radius:10px;z-index:99999;font-family:sans-serif;display:none;pointer-events:none;`;
        msgBox.textContent = "⚠️ Stream error detected. Switching channel...";
        (videoEl.parentElement || document.body).appendChild(msgBox);
        function showError(msg = "⚠️ Stream error detected") { msgBox.textContent = msg; msgBox.style.display = "block"; clearTimeout(msgBox._t); msgBox._t = setTimeout(() => { msgBox.style.display = "none"; }, 5000); }

        let lastPlaybackTime = 0, stallCount = 0;
        const deadChannels = new Map();
        setInterval(() => {
            if (!engine || engine._destroyed) return;
            if (videoEl.paused || videoEl.readyState < 2) return;
            const currentTime = videoEl.currentTime;
            if (currentTime === lastPlaybackTime) { stallCount++;
                const idx = engine.currentIndex || 0;
                if (stallCount < 3) { engine.playChannelSafe(idx); showError("🔄 Recovering stream..."); }
                else { deadChannels.set(idx, Date.now()); const nextIdx = (idx + 1) % engine.channels.length; showError(`🚨 Channel ${idx} seems dead. Switching...`); engine.playChannelSafe(nextIdx); stallCount = 0; }
            } else { stallCount = 0; }
            lastPlaybackTime = currentTime;
        }, 8000);

        setInterval(() => {
            if (!engine || engine._destroyed) return;
            const now = Date.now();
            for (const [idx, ts] of deadChannels.entries()) { if (now - ts > 60000) { console.log(`♻️ Retrying previously dead channel ${idx}`); deadChannels.delete(idx); } }
        }, 30000);

        let startIndex = 0; for (let i = 0; i < channelList.length; i++) { const ch = channelList[i]; if ((ch.url && ch.url.length) || (ch.qualities && Object.keys(ch.qualities).length)) { startIndex = i; break; } }
        engine.playChannelSafe(startIndex);

        if (typeof loadChannels === 'function') loadChannels();
        window.addEventListener('beforeunload', () => engine.destroy());
        console.log("🚀 IPTV God-Mode AI Engine initialized with adaptive SuperSonic & dead-channel recovery");
    } catch (e) { console.error("❌ Failed to initialize IPTV engine:", e); }
});










// adaptive-tier-player.js
// Fully merged adaptive-tier-player with auto screen-resize for all devices

/* QUALITY TIERS (ascending):
   - med : up to 480p
   - hd  : up to 720p
   - fhd : up to 1080p
   - 4k  : 2160p+
*/
const QUALITY_TIERS = [
  { key: 'med', name: 'Med',  maxHeight: 480,  maxBitrate: 1_000_000 },
  { key: 'hd',  name: 'HD',   maxHeight: 720,  maxBitrate: 2_500_000 },
  { key: 'fhd', name: 'FHD',  maxHeight: 1080, maxBitrate: 5_000_000 },
  { key: '4k',  name: '4K',   maxHeight: 2160, maxBitrate: Infinity }
];

// Runtime mutable allowed tiers
const ALLOWED_TIERS = QUALITY_TIERS.map(t => t.key);
// ----------------------------- housekeeping -----------------------------
let bufferWatcher = null;
let recentBitrates = [];
const PRELOAD_RANGE = 2;
const PRELOAD_QUALITIES = 5;

const _origPrewarm = (typeof prewarmSurroundingChannels === 'function') ? prewarmSurroundingChannels : null;

// ---------------------- Connection-aware caps ------------------------
const CONNECTION_CAP_MAP = {
  'slow-2g': { maxBandwidth: 80000, suggested: 'very low (~144p)' },   // ~80 kbps
  '2g':      { maxBandwidth: 150000, suggested: 'very low (~240p)' },  // ~150 kbps
  '3g':      { maxBandwidth: 700000, suggested: 'low (~480p)' },       // ~700 kbps
  '4g':      { maxBandwidth: 2500000, suggested: 'medium (~720p)' },   // ~2.5 Mbps
  '5g':      { maxBandwidth: undefined, suggested: 'high (>=1080p)' },  // no cap
  'wifi':    { maxBandwidth: undefined, suggested: 'full quality' },
  'saveData':{ maxBandwidth: 120000, suggested: 'very low (save-data)' },
  'unknown': { maxBandwidth: 1200000, suggested: 'default (~1.2Mbps)' }
};

function getConnectionCategory() {
  try {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!conn) return 'unknown';
    if (conn.saveData) return 'saveData';
    if (conn.type) {
      if (conn.type === 'wifi') return 'wifi';
      if (conn.type === 'cellular') {
        const et = (conn.effectiveType || '').toLowerCase();
        if (et.includes('slow-2g')) return 'slow-2g';
        if (et.includes('2g')) return '2g';
        if (et.includes('3g')) return '3g';
        if (et.includes('4g')) return '4g';
        return '3g';
      }
    }
    if (conn.effectiveType) {
      const et = conn.effectiveType.toLowerCase();
      if (et === 'slow-2g') return 'slow-2g';
      if (et === '2g') return '2g';
      if (et === '3g') return '3g';
      if (et === '4g') return '4g';
    }
    if (typeof conn.downlink === 'number') {
      // downlink is in Mbps
      if (conn.downlink >= 10) return 'wifi';
      if (conn.downlink >= 2.5) return '4g';
      if (conn.downlink >= 0.5) return '3g';
      return '2g';
    }
  } catch (e) {
    // ignore
  }
  return 'unknown';
}

function getMeasuredDownlinkBitsPerSec() {
  try {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!conn || typeof conn.downlink !== 'number') return undefined;
    return conn.downlink * 1_000_000;
  } catch (e) { return undefined; }
}

function getEffectiveMaxBandwidth(category) {
  const entry = CONNECTION_CAP_MAP[category] || CONNECTION_CAP_MAP['unknown'];
  const configuredCap = entry?.maxBandwidth; // bits/s or undefined
  const measured = getMeasuredDownlinkBitsPerSec(); // bits/s or undefined
  const SAFETY_RATIO = 0.8; // leave headroom

  if (typeof measured === 'number' && measured > 0) {
    const safetyLimit = Math.max(10000, Math.floor(measured * SAFETY_RATIO)); // min guard
    if (typeof configuredCap === 'undefined' || configuredCap === null) {
      return safetyLimit;
    } else {
      return Math.min(configuredCap, safetyLimit);
    }
  }

  return configuredCap;
}

// ---------------------- Tier helpers ------------------------
function tierByKey(key) { return QUALITY_TIERS.find(t => t.key === key) || QUALITY_TIERS[0]; }

function chooseAllowedTierForBandwidth(effectiveMax) {
  const allowed = ALLOWED_TIERS.map(k => tierByKey(k));
  if (!allowed.length) return tierByKey('med');
  if (typeof effectiveMax !== 'number' || !isFinite(effectiveMax)) return allowed[allowed.length-1];
  for (let i = 0; i < allowed.length; i++) if (effectiveMax <= allowed[i].maxBitrate) return allowed[i];
  return allowed[allowed.length-1];
}

// chooseAllowedTierForBandwidth returns a tier object {key,name,...}
function chooseAllowedTierForBandwidth(effectiveMax) {
  const allowed = ALLOWED_TIERS.map(k => tierByKey(k));
  if (allowed.length === 0) return tierByKey('med');

  if (typeof effectiveMax !== 'number' || !isFinite(effectiveMax)) {
    // no measured cap -> return highest allowed
    return allowed[allowed.length - 1];
  }

  // pick lowest tier whose maxBitrate is >= effectiveMax, otherwise highest allowed
  for (let i = 0; i < allowed.length; i++) {
    if (effectiveMax <= allowed[i].maxBitrate) return allowed[i];
  }
  return allowed[allowed.length - 1];
}

// ---------------------- HLS helpers ------------------------
function mapHlsLevelsToTiers(hlsInstance) {
  const mapping = {};
  try {
    const levels = hlsInstance.levels || [];
    for (let i = 0; i < levels.length; i++) {
      const L = levels[i];
      // Hls.js provides .height and .bitrate on many variants; try a few fallbacks
      const height = L.height || (L.attrs && L.attrs.RESOLUTION && parseInt(L.attrs.RESOLUTION.split('x')[1], 10)) || 0;
      // choose tier by height
      for (let j = 0; j < QUALITY_TIERS.length; j++) {
        if (height <= QUALITY_TIERS[j].maxHeight) {
          mapping[QUALITY_TIERS[j].key] = Math.max(mapping[QUALITY_TIERS[j].key] || -1, i);
          break;
        }
      }
    }
    // backfill missing tiers from nearest neighbors
    const keys = QUALITY_TIERS.map(t => t.key);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      if (typeof mapping[k] === 'undefined') {
        // try lower/higher
        for (let j = i+1; j < keys.length; j++) if (typeof mapping[keys[j]] !== 'undefined') { mapping[k] = mapping[keys[j]]; break; }
        if (typeof mapping[k] === 'undefined') for (let j = i-1; j >= 0; j--) if (typeof mapping[keys[j]] !== 'undefined') { mapping[k] = mapping[keys[j]]; break; }
      }
    }
  } catch (e) { /* best-effort */ }
  return mapping; // tierKey -> levelIndex
}

function chooseHlsLevelByTier(hlsInstance, desiredTierKey) {
  try {
    const levels = hlsInstance.levels || [];
    if (!levels.length) return -1;
    const mapping = mapHlsLevelsToTiers(hlsInstance);
    const idx = mapping[desiredTierKey];
    if (typeof idx === 'number' && idx >= 0) return idx;
    // fallback: pick highest level whose height <= tier's maxHeight
    const tier = tierByKey(desiredTierKey);
    for (let i = levels.length - 1; i >= 0; i--) {
      const h = levels[i].height || 0;
      if (h <= tier.maxHeight) return i;
    }
    return 0;
  } catch (e) { return -1; }
}

function enforceHlsTierSwitching(hlsInstance, allowedTiers = ALLOWED_TIERS) {
  if (!hlsInstance) return;
  let mapping = mapHlsLevelsToTiers(hlsInstance);
  hlsInstance.on(Hls.Events.MANIFEST_PARSED, () => { mapping = mapHlsLevelsToTiers(hlsInstance); });

  hlsInstance.on(Hls.Events.LEVEL_SWITCHING, (event, data) => {
    try {
      const desired = data.level;
      // build allowed indices from mapping
      const allowedIdx = [];
      for (const t of allowedTiers) {
        const idx = mapping[t];
        if (typeof idx === 'number' && idx >= 0) allowedIdx.push(idx);
      }
      if (!allowedIdx.length) return;
      // find nearest allowed to desired
      let best = allowedIdx[0];
      let bestDist = Math.abs(desired - best);
      for (let i = 1; i < allowedIdx.length; i++) {
        const d = Math.abs(desired - allowedIdx[i]);
        if (d < bestDist) { bestDist = d; best = allowedIdx[i]; }
      }
      if (best !== desired) {
        hlsInstance.currentLevel = best;
        hlsInstance.nextLevel = best;
        hlsInstance.autoLevelCapping = best;
        console.log('🎚️ HLS coerced', desired, '->', best);
      }
    } catch (e) {}
  });

  hlsInstance.on(Hls.Events.ERROR, (event, data) => { if (data && data.fatal) mapping = mapHlsLevelsToTiers(hlsInstance); });
}

// ---------------------- Engine/DASH helpers ------------------------
function mapEngineQualitiesToTiers(engineOrPlayer) {
  const mapping = {};
  try {
    let qualities = [];
    if (Array.isArray(engineOrPlayer.availableQualities)) {
      qualities = engineOrPlayer.availableQualities;
    } else if (typeof engineOrPlayer.getVariantTracks === 'function') {
      qualities = engineOrPlayer.getVariantTracks().map((t, idx) => ({ bitrate: t.bandwidth || t.bitrate, height: t.height, index: idx }));
    } else if (typeof engineOrPlayer.getBitrateInfoListFor === 'function') {
      qualities = engineOrPlayer.getBitrateInfoListFor('video') || [];
    } else if (typeof engineOrPlayer.getTracks === 'function') {
      qualities = engineOrPlayer.getTracks().filter(t => t.type === 'video');
    }

    for (let i = 0; i < qualities.length; i++) {
      const q = qualities[i];
      const height = q.height || q.resolution?.height || 0;
      for (let j = 0; j < QUALITY_TIERS.length; j++) {
        if (height <= QUALITY_TIERS[j].maxHeight) {
          mapping[QUALITY_TIERS[j].key] = Math.max(mapping[QUALITY_TIERS[j].key] || -1, i);
          break;
        }
      }
    }

    // backfill
    const keys = QUALITY_TIERS.map(t => t.key);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      if (typeof mapping[k] === 'undefined') {
        for (let j = i+1; j < keys.length; j++) if (mapping[keys[j]] >= 0) { mapping[k] = mapping[keys[j]]; break; }
        if (typeof mapping[k] === 'undefined') for (let j = i-1; j >= 0; j--) if (mapping[keys[j]] >= 0) { mapping[k] = mapping[keys[j]]; break; }
      }
    }
  } catch (e) {}
  return mapping; // tierKey -> qualityIndex
}

function enforceEngineTier(engineOrPlayer, allowedTiers = ALLOWED_TIERS) {
  try {
    const map = mapEngineQualitiesToTiers(engineOrPlayer);
    // prefer highest allowed
    for (const tierKey of allowedTiers.slice().reverse()) {
      const idx = map[tierKey];
      if (typeof idx === 'number' && idx >= 0) {
        if (typeof engineOrPlayer.forceQuality === 'function') { engineOrPlayer.forceQuality(idx); console.log('⚙️ Engine forced to', tierKey, idx); return true; }
        if (typeof engineOrPlayer.selectTrack === 'function') { try { engineOrPlayer.selectTrack(idx); return true; } catch (e) {} }
      }
    }
    // fallback: configure ABR maxBandwidth to lowest allowed tier to avoid excessive consumption
    const lowestAllowedKey = (allowedTiers && allowedTiers[0]) ? allowedTiers[0] : QUALITY_TIERS[0].key;
    const lowestAllowed = tierByKey(lowestAllowedKey);
    const capBitrate = lowestAllowed?.maxBitrate || null;
    if (capBitrate && typeof engineOrPlayer.configure === 'function') {
      try { engineOrPlayer.configure?.({ abr: { restrictions: { maxBandwidth: capBitrate } } }); console.log('⚙️ Engine applied fallback maxBandwidth', capBitrate); } catch (e) {}
    }
  } catch (e) { console.warn('enforceEngineTier failed', e); }
  return false;
}

// ---------------------- Promotion / Apply logic ------------------------
function promoteToHighestAllowedTierNow() {
  try {
    const category = getConnectionCategory();
    const effectiveMax = getEffectiveMaxBandwidth(category);
    const desiredTier = chooseAllowedTierForBandwidth(effectiveMax);
    console.log('📶 Promoting to allowed tier', desiredTier.key, 'for effectiveMax', effectiveMax);

    // HLS
    if (window.hls) {
      try {
        const level = chooseHlsLevelByTier(window.hls, desiredTier.key);
        if (level >= 0) {
          window.hls.currentLevel = level;
          window.hls.nextLevel = level;
          window.hls.autoLevelCapping = level;
          console.log('📶 HLS set to tier', desiredTier.key, 'level', level);
        }
        enforceHlsTierSwitching(window.hls, ALLOWED_TIERS);
      } catch (e) { console.warn('HLS promotion error', e); }
    }

    // DASH/player
    try {
      if (typeof player !== 'undefined' && player?.configure) {
        try { player.configure({ abr: { enabled: false } }); } catch (e) {}
        enforceEngineTier(player, ALLOWED_TIERS);
      }
    } catch (e) { console.warn('player promotion failed', e); }

    // Engine
    try { if (window.engine) enforceEngineTier(window.engine, ALLOWED_TIERS); } catch (e) { console.warn('engine promotion failed', e); }
  } catch (e) { console.warn('promoteToHighestAllowedTierNow error', e); }
}

function applyConnectionCaps({ forceCategory } = {}) {
  const category = forceCategory || getConnectionCategory();
  const entry = CONNECTION_CAP_MAP[category] || CONNECTION_CAP_MAP['unknown'];
  const effectiveMax = getEffectiveMaxBandwidth(category);
  console.log(`🔗 Connection category: ${category} — suggested: ${entry.suggested} — effective cap: ${effectiveMax ?? 'none'}`);

  // For tier model: pick allowed tier and enforce across players
  try { promoteToHighestAllowedTierNow(); } catch (e) { console.warn('applyConnectionCaps failed', e); }

  // mobile teardown / low-bit rate
  try {
    const onMobile = isOnMobileData();
    if (onMobile) {
      teardownPrewarmedResources();
      forceLowBitrateNow();
    } else {
      removeLowBitrateCap();
      const cat = getConnectionCategory();
      if (cat === 'wifi' || cat === '5g') promoteToHighestAllowedTierNow();
    }
  } catch (e) {}

  return { category, effectiveMax, suggested: entry.suggested };
}

function setCustomConnectionCap(category, maxBandwidthBitsPerSec, suggestionText) {
  CONNECTION_CAP_MAP[category] = { maxBandwidth: maxBandwidthBitsPerSec, suggested: suggestionText || '' };
  console.log('Custom cap set for', category, CONNECTION_CAP_MAP[category]);
}

// ---------------------- Network & Prewarm helpers ------------------------
function isOnMobileData() {
  try {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!conn) return false;
    if (conn.type === 'cellular') return true;
    if (conn.effectiveType && /^(2g|3g|4g|cellular)/i.test(conn.effectiveType)) return true;
    return false;
  } catch (e) { return false; }
}

function prewarmSurroundingChannelsWrapper(index) {
  if (isOnMobileData()) {
    console.log('📱 Skipping prewarm: on mobile data');
    return;
  }
  if (_origPrewarm) return _origPrewarm(index);
}
try { prewarmSurroundingChannels = prewarmSurroundingChannelsWrapper; } catch (e) {}

// teardown prewarm resources
function teardownPrewarmedResources() {
  try {
    console.log('🧹 Tearing down prewarmed resources (best-effort).');
    if (Array.isArray(window.prewarmedHlsInstances)) {
      window.prewarmedHlsInstances.forEach(h => { try { h.destroy?.(); } catch (e) {} });
      window.prewarmedHlsInstances.length = 0;
    }
    if (Array.isArray(window.prewarmedDashPlayers)) {
      window.prewarmedDashPlayers.forEach(p => { try { p.destroy?.(); } catch (e) {} });
      window.prewarmedDashPlayers.length = 0;
    }
    if (Array.isArray(window.prewarmedEngineChannels)) {
      window.prewarmedEngineChannels.forEach(e => { try { e.stop?.(); } catch (err) {} });
      window.prewarmedEngineChannels.length = 0;
    }
    ['prewarmedHlsInstances','prewarmedDashPlayers','prewarmedEngineChannels'].forEach(k => { if (window[k] && Array.isArray(window[k])) window[k] = []; });
    if (typeof window.teardownPrewarmedChannels === 'function') try { window.teardownPrewarmedChannels(); } catch (e) {}
  } catch (e) { console.warn('Teardown prewarmed resources encountered an error:', e); }
}

// ---------------------- Downgrade & restore ------------------------
function forceLowBitrateNow() {
  try {
    console.log('📉 Forcing low bitrate (best-effort) for current playback.');

    // HLS: force med tier if available
    if (window.hls) {
      try {
        const medIdx = chooseHlsLevelByTier(window.hls, 'med');
        if (medIdx >= 0) {
          window.hls.currentLevel = medIdx;
          window.hls.nextLevel = medIdx;
          window.hls.autoLevelCapping = medIdx;
          console.log('📉 HLS: forced Med level', medIdx);
        }
      } catch (e) { console.warn('HLS downgrade failed', e); }
    }

    // DASH/player: restrict to med max bitrate
    if (typeof player !== 'undefined' && player && typeof player.configure === 'function') {
      try { player.configure({ abr: { restrictions: { maxBandwidth: QUALITY_TIERS.find(t => t.key === 'med').maxBitrate } } }); console.log('📉 DASH/player: applied ABR maxBandwidth for Med'); } catch (e) { console.warn('Player ABR cap failed', e); }
    }

    // engine
    if (window.engine) {
      try { enforceEngineTier(window.engine, ['med']); } catch (e) { console.warn('Engine downgrade failed', e); }
    }

    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn && conn.saveData) console.log('💾 saveData is enabled; preferring lowest-quality streams by default.');
  } catch (e) { console.warn('forceLowBitrateNow error:', e); }
}

function removeLowBitrateCap() {
  try {
    console.log('🔼 Removing mobile bitrate caps (best-effort).');
    if (window.hls) try { window.hls.autoLevelCapping = -1; window.hls.nextLevel = -1; } catch (e) {}
    if (typeof player !== 'undefined' && player && typeof player.configure === 'function') try { player.configure({ abr: { restrictions: { maxBandwidth: undefined } } }); } catch (e) {}
    if (window.engine) {
      try { if (typeof window.engine.configure === 'function') window.engine.configure({ abr: { restrictions: { maxBandwidth: undefined } } }); } catch (e) {}
      try { if (typeof window.engine.removeMaxBitrate === 'function') window.engine.removeMaxBitrate(); } catch (e) {}
    }
  } catch (e) { console.warn('removeLowBitrateCap error:', e); }
}

// ---------------------- Connection-change listener ------------------------
(function addConnectionChangeListener() {
  try {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn && typeof conn.addEventListener === 'function') {
      conn.addEventListener('change', () => {
        try {
          const nowOnMobile = isOnMobileData();
          console.log('🔁 Network connection changed. onMobileData=', nowOnMobile);
          const info = applyConnectionCaps();
          console.log('🔁 applyConnectionCaps result:', info);
          try { if (!nowOnMobile) { const cat = getConnectionCategory(); if (cat === 'wifi' || cat === '5g') { promoteToHighestAllowedTierNow(); } } } catch (e) {}
        } catch (e) { console.warn('Connection change handler error', e); }
      });
    }
  } catch (e) { /* ignore */ }
})();

// Apply connection caps once at startup to set sensible defaults
try { applyConnectionCaps(); } catch (e) { /* ignore */ }

// ---------------------- Dead stream detection ------------------------
function startDeadStreamWatchdog(channel, index) {
  try {
    if (bufferWatcher) clearInterval(bufferWatcher);
    let lastTime = (typeof video !== 'undefined' && video) ? video.currentTime : 0;
    let stuckCount = 0;
    bufferWatcher = setInterval(() => {
      try {
        if (!video || video.readyState < 2) return;
        const bufferedEnd = video.buffered.length ? video.buffered.end(video.buffered.length - 1) : 0;
        const bufferAhead = bufferedEnd - video.currentTime;
        if (bufferAhead < 0.5 || video.paused) {
          if (Math.abs(video.currentTime - lastTime) < 0.1) {
            stuckCount++;
            if (stuckCount >= 6) { // ~15s stuck
              clearInterval(bufferWatcher);
              console.warn(`${channel.name} seems dead. Restarting...`);
              restartChannel(channel, index);
            }
          } else stuckCount = 0;
        } else stuckCount = 0;
        lastTime = video.currentTime;
      } catch (e) {}
    }, 2500);
  } catch (e) {}
}

// ---------------------- Engine listeners ------------------------
function setupEngineListeners(channel) {
  if (!window.engine?.on) return;
  window.engine.on('error', () => { console.warn(`${channel.name} Engine error. Restarting...`); restartChannel(channel, currentChannelIndex); });
  window.engine.on('ready', () => { setupQualityControls(window.engine); updateAudioAndSubtitles(window.engine); enforceEngineTier(window.engine, ALLOWED_TIERS); });
  window.engine.on('stats', (stats) => { if (stats?.bitrate) { recentBitrates.push(stats.bitrate); if (recentBitrates.length > 20) recentBitrates.shift(); } });
}

// ---------------------- Mobile config helper ------------------------
function configureForMobileData({ playerInstance, hlsInstance } = {}) {
  try {
    if (playerInstance && typeof playerInstance.configure === 'function') {
      playerInstance.configure({ abr: { restrictions: { maxBandwidth: QUALITY_TIERS.find(t => t.key === 'med').maxBitrate } } });
      console.log('📉 Player configured: ABR maxBandwidth for Med');
    }
  } catch (e) { console.warn('Could not configure player ABR cap:', e); }
  try {
    if (hlsInstance) {
      const medIdx = chooseHlsLevelByTier(hlsInstance, 'med');
      if (medIdx >= 0) {
        hlsInstance.autoLevelCapping = medIdx;
        hlsInstance.currentLevel = medIdx;
        hlsInstance.nextLevel = medIdx;
      }
      console.log('📉 HLS instance prepared for Med');
    }
  } catch (e) { console.warn('Could not configure HLS instance:', e); }
}

// ---------------------- Flip channel (main playback switch) ------------------------
async function flipChannel(card, index) {
  if (typeof currentChannelIndex !== 'undefined' && index === currentChannelIndex) return;
  currentChannelIndex = index;
  const channel = channels[index];
  if (!channel) return;

  console.log('🎬 Switching to', channel.name);
  document.querySelectorAll('.channel').forEach(el => el.classList.remove('active', 'flipped'));
  if (card) card.classList.add('active', 'flipped');
  const channelNameEl = document.getElementById('channelName'); if (channelNameEl) channelNameEl.textContent = channel.name;
  try { localStorage.setItem('lastChannelIndex', index); } catch (e) {}
  if (typeof video !== 'undefined' && video) video.muted = false;

  // cleanup previous session
  if (window.hls) { try { window.hls.destroy(); } catch(e) {} window.hls = null; }
  if (bufferWatcher) { clearInterval(bufferWatcher); bufferWatcher = null; }
  try { await player.unload().catch(()=>{}); } catch(e) {}

  const onMobile = isOnMobileData();
  if (onMobile) {
    console.log('📱 Mobile data detected: disabling preloading & preferring low bitrate.');
    configureForMobileData({ playerInstance: player, hlsInstance: window.hls });
    teardownPrewarmedResources();
  }

  try { applyConnectionCaps(); } catch (e) {}
  try { const cat = getConnectionCategory(); if (cat === 'wifi' || cat === '5g') promoteToHighestAllowedTierNow(); } catch (e) {}

  // Engine preferred
  const canUseEngine = window.engine && channel.engineSupported;
  if (canUseEngine) {
    try {
      window.engine.playChannelSafe(index);
      currentFormat = 'engine';
      setupEngineListeners(channel);
      startDeadStreamWatchdog(channel, index);
      if (!onMobile) prewarmSurroundingChannels(index);
      if (onMobile) try { if (typeof window.engine.configure === 'function') window.engine.configure?.({ abr: { restrictions: { maxBandwidth: QUALITY_TIERS.find(t => t.key === 'med').maxBitrate } } }); } catch (e) {}
      console.log(`🚀 Playing ${channel.name} via Engine (preferred)`);
      return;
    } catch (e) { console.warn(`⚠️ Engine failed for ${channel.name}, falling back`, e); }
  }

  // DASH fallback
  if (channel.manifestUri?.endsWith('.mpd')) {
    try {
      const dashConfig = { drm: { clearKeys: channel.clearKey || {} }, streaming: { lowLatencyMode: true, jumpLargeGaps: true }, abr: { enabled: true } };
      if (onMobile && player) dashConfig.abr = { enabled: true, restrictions: { maxBandwidth: QUALITY_TIERS.find(t => t.key === 'med').maxBitrate } };
      player.configure(dashConfig);
      player.addEventListener('error', () => restartChannel(channel, index));
      await player.load(channel.manifestUri);
      // enforce tier
      enforceEngineTier(player, ALLOWED_TIERS);
      await (typeof video !== 'undefined' && video ? video.play().catch(()=>{}) : Promise.resolve());
      currentFormat = 'dash';
      startDeadStreamWatchdog(channel, index);
      if (!onMobile) prewarmSurroundingChannels(index);
      console.log(`✅ Playing ${channel.name} via DASH fallback`);
    } catch (e) { console.warn('DASH fallback failed', e); restartChannel(channel, index); }
    return;
  }

  // HLS fallback
  if (channel.url?.endsWith('.m3u8')) {
    if (!Hls.isSupported()) {
      video.src = channel.url;
      video.addEventListener('loadedmetadata', () => video.play().catch(()=>{}));
      startDeadStreamWatchdog(channel, index);
      if (!onMobile) prewarmSurroundingChannels(index);
      return;
    }

    window.hls = new Hls({ enableWorker:true, lowLatencyMode:true });
    window.hls.attachMedia(video);
    window.hls.on(Hls.Events.MEDIA_ATTACHED, () => window.hls.loadSource(channel.url));
    window.hls.on(Hls.Events.MANIFEST_PARSED, (event, data) => {
      try {
        const cat = getConnectionCategory();
        const cap = getEffectiveMaxBandwidth(cat);
        const desiredTier = chooseAllowedTierForBandwidth(cap);
        const level = chooseHlsLevelByTier(window.hls, desiredTier.key);
        if (level >= 0) {
          window.hls.currentLevel = level;
          window.hls.nextLevel = level;
          window.hls.autoLevelCapping = level;
          console.log('📉 HLS: applied tier level at manifest parsed ->', level, 'tier:', desiredTier.key);
        } else {
          try { window.hls.autoLevelCapping = -1; } catch (e) {}
        }
      } catch (e) { console.warn('HLS manifest handling error', e); }

      if (onMobile) {
        try {
          const medIdx = chooseHlsLevelByTier(window.hls, 'med');
          if (medIdx >= 0) { window.hls.currentLevel = medIdx; window.hls.nextLevel = medIdx; window.hls.autoLevelCapping = medIdx; }
          console.log('📉 HLS: forced Med for mobile at manifest parsed');
        } catch (e) { console.warn('Could not force mobile HLS level', e); }
      }

      // enforce tier switching
      enforceHlsTierSwitching(window.hls, ALLOWED_TIERS);

      video.play().catch(()=>{});
      currentFormat = 'hls';
      startDeadStreamWatchdog(channel, index);
      if (!onMobile) prewarmSurroundingChannels(index);
      console.log(`✅ Playing ${channel.name} via HLS fallback`);
    });
    window.hls.on(Hls.Events.ERROR, (event, data) => { if (data.fatal) restartChannel(channel, index); });
    return;
  }

  // Unsupported
  restartChannel(channel, index);
}

// ---------------------- Runtime helpers exposed ------------------------
function setAllowedTiers(tiersArray) {
  if (!Array.isArray(tiersArray) || tiersArray.length === 0) return;
  const valid = QUALITY_TIERS.map(t => t.key);
  const normalized = tiersArray.map(t => (typeof t === 'string' ? t.toLowerCase() : '')).filter(t => valid.includes(t));
  if (!normalized.length) return;
  ALLOWED_TIERS.length = 0;
  normalized.forEach(t => ALLOWED_TIERS.push(t));
  console.log('Allowed tiers updated to', ALLOWED_TIERS);
  try { applyConnectionCaps(); } catch (e) {}
}

// Expose a simple UI helper to let users choose a tier manually (optional)
function createTierSelectorUI(containerEl) {
  if (!containerEl) return null;
  const select = document.createElement('select');
  select.setAttribute('aria-label', 'Quality tier');
  for (const t of QUALITY_TIERS) {
    const opt = document.createElement('option'); opt.value = t.key; opt.textContent = t.name; select.appendChild(opt);
  }
  select.value = ALLOWED_TIERS[ALLOWED_TIERS.length - 1] || QUALITY_TIERS[QUALITY_TIERS.length - 1].key;
  select.addEventListener('change', () => {
    const chosenKey = select.value;
    try {
      // enforce chosen tier immediately across players
      if (window.hls) {
        const idx = chooseHlsLevelByTier(window.hls, chosenKey);
        if (idx >= 0) { window.hls.currentLevel = idx; window.hls.nextLevel = idx; window.hls.autoLevelCapping = idx; }
      }
      if (typeof player !== 'undefined' && player?.configure) { try { player.configure({ abr: { enabled: false } }); } catch (e) {} }
      if (window.engine) enforceEngineTier(window.engine, [chosenKey]);
      // update allowed tiers to reflect manual override
      setAllowedTiers([chosenKey]);
      console.log('User selected tier', chosenKey);
    } catch (e) { console.warn('Tier selector failed', e); }
  });
  containerEl.appendChild(select);
  return select;
}

// ---------------------- Public API ------------------------
window.tieredPlayer=window.tieredPlayer||{};
window.tieredPlayer.setAllowedTiers=function(tiersArray){if(!Array.isArray(tiersArray)||tiersArray.length===0)return;ALLOWED_TIERS.length=0;tiersArray.forEach(t=>ALLOWED_TIERS.push(t));promoteToHighestAllowedTierNow();};
window.tieredPlayer.applyConnectionCaps=applyConnectionCaps;
window.tieredPlayer.promoteToHighestAllowedTierNow=promoteToHighestAllowedTierNow;


// End of adaptive-tier-player.js
































settingsBtn.addEventListener('click', (e) => {
  e.stopPropagation(); // prevent the document click from firing

  const wasHidden = settingsDropdown.classList.contains('hidden');
  settingsDropdown.classList.toggle('hidden');

  // Spin the gear
  settingsBtn.classList.add('animate-spin-once');
  setTimeout(() => settingsBtn.classList.remove('animate-spin-once'), 600);

  // Trigger slide animation only when opening
  if (wasHidden) {
    settingsDropdown.classList.remove('animate-slide-fade'); // reset if needed
    void settingsDropdown.offsetWidth; // force reflow
    settingsDropdown.classList.add('animate-slide-fade');
  }
});

// Click outside to close
document.addEventListener('click', (e) => {
  if (!settingsDropdown.classList.contains('hidden') && !settingsDropdown.contains(e.target) && e.target !== settingsBtn) {
    settingsDropdown.classList.add('hidden');
  }
});


// ========================
// Global Variables
// ========================
let currentChannelIndex = -1;
let selectedCategory = 'Local';
let searchQuery = '';
let focusedCategoryIndex = 0;
let focusedChannelIndex = 0;
const allowedCategories = [
  'Local','Sports','Kids','Movies','Astro','Music',
  'Comedy','Documentary','News',
  'Tambay Pelikula','English Pelikula'
];
const categoryIcons = {
  'News':'https://tse2.mm.bing.net/th/id/OIP.nvNZLt4SKTYjDeiZUn1BWAHaHa?pid=Api&P=0&h=180',
  'Sports':'https://tse2.mm.bing.net/th/id/OIP.UnBKRjopwfJdahd_GaYehAHaHa?pid=Api&P=0&h=180',
  'Kids':'https://tse2.mm.bing.net/th/id/OIP.OatkCxJFF9XXxQUihnUZGQHaHa?pid=Api&P=0&h=180',
  'Movies':'https://tse4.mm.bing.net/th/id/OIP.RhZh6EzbP0yfnmWnIirRvgHaHa?pid=Api&P=0&h=180',
  'Music':'https://tse2.mm.bing.net/th/id/OIP.tDbroc3v2uBQvQN2H0KLYwHaHa?pid=Api&P=0&h=180',
  'Comedy':'https://tse3.mm.bing.net/th/id/OIP.Jy0hz_kjnGds4qFsfnev6QHaEm?pid=Api&P=0&h=180',
  'Documentary':'https://tse2.mm.bing.net/th/id/OIP.qTBgSWbipk5WJ152G705IQHaHa?pid=Api&P=0&h=180',
  'Local':'https://tse2.mm.bing.net/th/id/OIP.bvCaB1ipTy1JJXAY-5RSmwHaHa?pid=Api&P=0&h=180',
  'Astro':'https://tse4.mm.bing.net/th/id/OIP.mEJfZDySVRNMJpey8XQ43gHaEK?pid=Api&P=0&h=180',
  'Tambay Pelikula':'https://tse2.mm.bing.net/th/id/OIP.kkgV9xO10Nu7ffzkH4yh1wHaHd?pid=Api&P=0&h=180',
  'English Pelikula':'https://tse1.mm.bing.net/th/id/OIP.sM8r4kuVbiqhZ_LSGGdT3wHaE8?pid=Api&P=0&h=180'
};
const fadeDuration = 250;


// ========================
// Helper Functions
// ========================
function debounce(fn, delay) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), delay);
  };
}

// ========================
// Channel / Category Logic
// ========================
// script.js
let channels = [];

async function loadChannels() {
  try {
    const res = await fetch("/channels");
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    channels = await res.json();

    renderCategoryFilters();
    renderChannelRows();

    const savedIndex = parseInt(localStorage.getItem("lastChannelIndex"));
    const initialIndex = (!isNaN(savedIndex) && channels[savedIndex]) ? savedIndex : 0;
    const card = document.querySelector(`.channel[data-index="${initialIndex}"]`);
    if (card) flipChannel(card, initialIndex);

  } catch (err) {
    console.error("❌ Failed to load channels:", err);
    const container = document.querySelector("#channels-container");
    if (container) container.innerHTML = "<p style='color:red;'>Failed to load channels.</p>";
  }
}

document.addEventListener("DOMContentLoaded", loadChannels);






// ========================
// Category & Channel Rendering
// ========================
function renderCategoryFilters() {
  const filterBar = document.getElementById('categoryFilterBar');
  filterBar.innerHTML = '';

  const categories = allowedCategories.filter(cat => channels.some(c => c.category === cat));
  categories.forEach((cat, idx) => {
    const btn = document.createElement('button');
    btn.className = `category-tab flex flex-col items-center px-4 py-1 rounded-lg cursor-pointer transition-transform ${
      selectedCategory === cat ? 'scale-110 border-2 border-cyan-400' : 'border border-transparent'
    }`;
    btn.setAttribute('role','tab');
    btn.setAttribute('aria-selected', selectedCategory === cat ? 'true':'false');
    btn.setAttribute('tabindex', focusedCategoryIndex === idx ? '0':'-1');
    btn.dataset.index = idx;

    btn.onclick = () => {
      if (selectedCategory !== cat) {
        selectedCategory = cat;
        focusedCategoryIndex = idx;
        focusedChannelIndex = 0;
        animateCategoryChange();
      }
    };

    const img = document.createElement('img');
    img.src = categoryIcons[cat] || 'https://via.placeholder.com/40';
    img.alt = cat;
    img.style.width = '40px';
    img.style.height = '40px';
    img.style.objectFit = 'contain';
    img.style.marginBottom = '4px';

    const label = document.createElement('span');
    label.textContent = cat;
    label.className = 'text-sm font-semibold text-white select-none';

    btn.appendChild(img);
    btn.appendChild(label);
    filterBar.appendChild(btn);
  });
}

function renderChannelRows() {
  const container = document.getElementById('channelCategories');
  container.style.transition = `opacity ${fadeDuration}ms ease`;
  container.style.opacity = '0';

  debounce(() => {
    container.innerHTML = '';
    if (!selectedCategory) return;

    const filteredChannels = channels.filter(c =>
      c.category === selectedCategory &&
      c.name.toLowerCase().includes(searchQuery.toLowerCase())
    );

    if (filteredChannels.length === 0) {
      container.innerHTML = '<p class="text-white px-4">No channels found.</p>';
      container.style.opacity = '1';
      return;
    }

    const neonClassMap = {
      'Sports':'neon-cyan','Music':'neon-cyan','News':'neon-red',
      'Movies':'neon-orange','Kids':'neon-pink','Comedy':'neon-yellow',
      'Documentary':'neon-purple','Local':'neon-blue',
      'Tambay Pelikula':'neon-brown','English Pelikula':'neon-brown','Astro':'neon-brown'
    };
    const neonClass = neonClassMap[selectedCategory] || 'neon-blue';

    const section = document.createElement('div');
    section.innerHTML = `
      <h2 class="text-xl font-bold mb-2 ${neonClass} pulse-text">${selectedCategory}</h2>
      <div class="scroll-x flex overflow-x-auto gap-4 py-2 px-1" role="list" tabindex="0">
        ${filteredChannels.map((channel,i) => `
          <div tabindex="${i === focusedChannelIndex ? '0':'-1'}" class="channel flip-card text-center flex-shrink-0 w-24 min-w-[6rem]" data-index="${channels.indexOf(channel)}" data-name="${channel.name}" role="listitem" aria-selected="${i === focusedChannelIndex}">
            <div class="flip-inner w-full h-full relative">
              <div class="flip-front aspect-square w-full rounded-full overflow-hidden shadow-lg">
                <img src="${channel.logo}" alt="${channel.name}" class="w-full h-full object-cover rounded-full" />
              </div>
              <div class="flip-back aspect-square absolute inset-0 rounded-full flex items-center justify-center text-[10px] font-bold text-white neon-text">NOW<br>PLAYING</div>
            </div>
            <p class="mt-1 text-xs font-bold text-cyan-300 max-w-[6rem] break-words whitespace-normal text-center neon-text leading-tight">${channel.name}</p>
          </div>
        `).join('')}
      </div>
    `;
    container.appendChild(section);

    setTimeout(()=>{container.style.opacity='1';},50);

    const channelElements = container.querySelectorAll('.channel');
    channelElements.forEach((card,idx)=>{
      card.onclick = () => { flipChannel(card, parseInt(card.dataset.index)); focusedChannelIndex=idx; updateChannelFocus(); };
      card.onfocus = () => { focusedChannelIndex=idx; updateChannelFocus(); };
    });

  },100)();
}

function animateCategoryChange() {
  const container = document.getElementById('channelCategories');
  container.style.opacity = '0';
  setTimeout(()=>{
    renderCategoryFilters();
    renderChannelRows();
    updateCategoryFocus();
    updateChannelFocus();
  }, fadeDuration);
}

function updateCategoryFocus() {
  const filterBar = document.getElementById('categoryFilterBar');
  filterBar.querySelectorAll('button').forEach((btn, idx)=>{
    btn.setAttribute('tabindex', focusedCategoryIndex===idx?'0':'-1');
    btn.setAttribute('aria-selected', selectedCategory===allowedCategories[idx]?'true':'false');
    btn.classList.toggle('focused', focusedCategoryIndex===idx);
    if(focusedCategoryIndex===idx && document.activeElement!==btn) btn.focus();
  });
}

function updateChannelFocus() {
  const container = document.getElementById('channelCategories');
  const channelsEls = container.querySelectorAll('.channel');
  channelsEls.forEach((ch, idx)=>{
    ch.setAttribute('tabindex', focusedChannelIndex===idx?'0':'-1');
    ch.setAttribute('aria-selected', focusedChannelIndex===idx?'true':'false');
    ch.classList.toggle('focused', focusedChannelIndex===idx);
    if(focusedChannelIndex===idx && document.activeElement!==ch) ch.focus();
  });
}


function showChannelInfoModal(channelIndex) {
  const filteredChannels = channels.filter(c => c.category===selectedCategory);
  const channel = filteredChannels[channelIndex];
  alert(`Info for channel: ${channel?channel.name:'Unknown'}`);
}

// ========================
// Key Navigation
// ========================
function handleKeyDown(event) {
  const filterBar = document.getElementById('categoryFilterBar');
  const channelContainer = document.getElementById('channelCategories');
  const channelElements = channelContainer.querySelectorAll('.channel');
  const active = document.activeElement;

  switch(event.key){
    case 'ArrowLeft': case 'Left':
      if(active.parentElement===filterBar && focusedCategoryIndex>0){focusedCategoryIndex--; selectedCategory=allowedCategories[focusedCategoryIndex]; animateCategoryChange(); focusedChannelIndex=0;}
      else if(active.classList.contains('channel') && focusedChannelIndex>0){focusedChannelIndex--; updateChannelFocus();}
      event.preventDefault(); break;

    case 'ArrowRight': case 'Right':
      if(active.parentElement===filterBar && focusedCategoryIndex<allowedCategories.length-1){focusedCategoryIndex++; selectedCategory=allowedCategories[focusedCategoryIndex]; animateCategoryChange(); focusedChannelIndex=0;}
      else if(active.classList.contains('channel') && focusedChannelIndex<channelElements.length-1){focusedChannelIndex++; updateChannelFocus();}
      event.preventDefault(); break;

    case 'ArrowUp': case 'Up':
      if(active.classList.contains('channel')) filterBar.querySelectorAll('button')[focusedCategoryIndex].focus();
      event.preventDefault(); break;

    case 'ArrowDown': case 'Down':
      if(active.parentElement===filterBar && channelElements.length>0){focusedChannelIndex=0; updateChannelFocus();}
      event.preventDefault(); break;

    case 'Enter': case ' ':
      if(active) active.click();
      event.preventDefault(); break;

    case 'Escape':
      if(active.classList.contains('channel')) filterBar.querySelectorAll('button')[focusedCategoryIndex].focus();
      event.preventDefault(); break;

    case 'i': case 'I':
      if(active.classList.contains('channel')) showChannelInfoModal(focusedChannelIndex);
      event.preventDefault(); break;

    default: break;
  }
}

// ========================
// Initialize
// ========================
function initialize() {
  shaka.polyfill.installAll();
  window.addEventListener('keydown', handleKeyDown);

  // Gear dropdown toggle
  const settingsBtn = document.getElementById('settingsBtn');
  const settingsDropdown = document.getElementById('settingsDropdown');
  settingsBtn.addEventListener('click', () => settingsDropdown.classList.toggle('hidden'));

  // Hide dropdowns on outside click
  document.addEventListener('click', (e)=>{
    const gearWrapper = settingsBtn;
    const qualityMenu = document.getElementById('qualityMenu');
    const qualityOptionsTrigger = document.getElementById('qualityOptionsTrigger');

    if(!gearWrapper.contains(e.target) && !qualityMenu.contains(e.target) && !qualityOptionsTrigger.contains(e.target)){
      settingsDropdown.classList.add('hidden');
      qualityMenu.classList.add('hidden');
      document.getElementById('qualityArrow').style.transform='rotate(0deg)';
    }
  });
}

document.addEventListener('DOMContentLoaded', initialize);










// Cache DOM references once
const searchBarContainer = document.getElementById('searchBarContainer');
const searchInput = document.getElementById('searchInput');
const searchToggle = document.getElementById('searchToggle');



// Optimized reusable debounce with immediate call & cancel support
function debounce(func, wait, immediate = true) {
  let timeout;
  function debounced(...args) {
    const callNow = immediate && !timeout;
    clearTimeout(timeout);
    timeout = setTimeout(() => {
      timeout = null;
      if (!immediate) func.apply(this, args);
    }, wait);
    if (callNow) func.apply(this, args);
  }
  debounced.cancel = () => clearTimeout(timeout);
  return debounced;
}

// Toggle search bar visibility and focus input with smooth animation
searchToggle.addEventListener('click', () => {
  if (!searchBarContainer.classList.contains('active')) {
    searchBarContainer.classList.add('active'); // Show the search bar container

    // Wait for the animation to complete before focusing the input
    requestAnimationFrame(() => {
      if ('requestIdleCallback' in window) {
        requestIdleCallback(() => searchInput.focus(), {timeout: 200});
      } else {
        setTimeout(() => searchInput.focus(), 100); // Ensure input is focused after animation
      }
    });
  }
});

// Debounced input handler with immediate call on first input for snappy UI
const handleInput = debounce((e) => {
  const val = e.target.value.trim().toLowerCase();
  if (val === searchQuery) return; // Avoid unnecessary renders
  searchQuery = val;

  // Schedule renderChannelRows at idle time for smoother UX
  if ('requestIdleCallback' in window) {
    requestIdleCallback(() => renderChannelRows());
  } else {
    // fallback
    setTimeout(() => renderChannelRows(), 50);
  }
}, 150, true);

searchInput.addEventListener('input', handleInput, { passive: true });

// Close search bar on outside click or ESC keypress
document.addEventListener('click', (e) => {
  if (!searchBarContainer.contains(e.target)) closeSearchBar();
}, { passive: true });

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && searchBarContainer.classList.contains('active')) {
    closeSearchBar();
  }
}, { passive: true });

// Reset and close the search bar cleanly
function closeSearchBar() {
  if (!searchBarContainer.classList.contains('active')) return;

  searchBarContainer.classList.remove('active');
  searchInput.value = '';
  searchQuery = '';
  handleInput.cancel?.();
  renderChannelRows();
}
 // Global track selectors
const audioSelect = document.getElementById('audioSelect');
const subtitleSelect = document.getElementById('subtitleSelect');
const audioOptions = document.getElementById('audioOptions');
const subtitleOptions = document.getElementById('subtitleOptions');

// Current playback state
let currentFormat = '';


// Track selector event listeners
audioSelect.addEventListener('change', () => {
  const lang = audioSelect.value;

  if (currentFormat === 'dash' && player) {
    player.selectAudioLanguage(lang);
  } else if (currentFormat === 'hls' && window.hls) {
    const index = window.hls.audioTracks.findIndex(t => t.lang === lang);
    if (index !== -1) window.hls.audioTrack = index;
  }
});

subtitleSelect.addEventListener('change', () => {
  const lang = subtitleSelect.value;

  if (currentFormat === 'dash' && player) {
    player.setTextTrackVisibility(lang !== 'off');
    if (lang !== 'off') player.selectTextLanguage(lang);
  } else if (currentFormat === 'hls') {
    const textTracks = video.textTracks;
    for (let i = 0; i < textTracks.length; i++) {
      textTracks[i].mode = (textTracks[i].language === lang) ? 'showing' : 'disabled';
    }
  }
});

// Update available audio and subtitle tracks
function updateAudioAndSubtitles() {
  audioSelect.innerHTML = '';
  subtitleSelect.innerHTML = '<option value="off">Off</option>';

  // DASH / Shaka Player
  if (currentFormat === 'dash' && player) {
    const audioLangs = [...new Set(player.getVariantTracks().map(t => t.audioLanguage))];
    audioLangs.forEach(lang => {
      const option = document.createElement('option');
      option.value = lang;
      option.textContent = lang.toUpperCase();
      audioSelect.appendChild(option);
    });
    audioOptions.classList.toggle('hidden', audioLangs.length === 0);

    const textTracks = player.getTextTracks();
    textTracks.forEach(track => {
      const option = document.createElement('option');
      option.value = track.language;
      option.textContent = track.language.toUpperCase();
      subtitleSelect.appendChild(option);
    });
    subtitleOptions.classList.toggle('hidden', textTracks.length === 0);

    if (textTracks.length > 0) {
      const enTrack = textTracks.find(t => t.language === 'en') || textTracks[0];
      player.selectTextLanguage(enTrack.language);
      player.setTextTrackVisibility(true);
      subtitleSelect.value = enTrack.language;
    }

  // HLS / Hls.js
  } else if (currentFormat === 'hls' && window.hls) {
    const hlsTracks = window.hls.audioTracks || [];
    const seenLangs = new Set();
    hlsTracks.forEach(track => {
      if (!seenLangs.has(track.lang)) {
        seenLangs.add(track.lang);
        const option = document.createElement('option');
        option.value = track.lang;
        option.textContent = track.lang.toUpperCase();
        audioSelect.appendChild(option);
      }
    });
    audioOptions.classList.toggle('hidden', seenLangs.size === 0);

    const textTracks = video.textTracks;
    const subtitleLangs = new Set();
    for (let i = 0; i < textTracks.length; i++) {
      const track = textTracks[i];
      if (!subtitleLangs.has(track.language)) {
        subtitleLangs.add(track.language);
        const option = document.createElement('option');
        option.value = track.language;
        option.textContent = track.language.toUpperCase();
        subtitleSelect.appendChild(option);
      }
    }
    subtitleOptions.classList.toggle('hidden', subtitleLangs.size === 0);

    for (let i = 0; i < textTracks.length; i++) {
      const track = textTracks[i];
      track.mode = (track.language === 'en') ? 'showing' : 'disabled';
      if (track.language === 'en') subtitleSelect.value = 'en';
    }
  }
}










function scrollChannelIntoView(card) {
  if (!card) return;
  const container = document.querySelector('.scroll-x');
  const cardLeft = card.offsetLeft;
  const cardWidth = card.offsetWidth;
  const containerWidth = container.offsetWidth;

  const targetScrollLeft = cardLeft - (containerWidth / 2) + (cardWidth / 2);

  container.scrollTo({
    left: targetScrollLeft,
    behavior: 'smooth'
  });
}

const channelCards = document.querySelectorAll('.channel');
let focusedIndex = 0;

function focusChannel(index) {
  if (index < 0 || index >= channelCards.length) return;
  channelCards[focusedIndex].classList.remove('focused');
  focusedIndex = index;
  channelCards[focusedIndex].classList.add('focused');
  channelCards[focusedIndex].scrollIntoView({ behavior: 'smooth', inline: 'center' });
  channelCards[focusedIndex].focus();
}

// Initial focus on first channel
focusChannel(0);

document.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowRight') {
    focusChannel(focusedIndex + 1);
    e.preventDefault();
  } else if (e.key === 'ArrowLeft') {
    focusChannel(focusedIndex - 1);
    e.preventDefault();
  } else if (e.key === 'Enter') {
    // Trigger channel click/play
    channelCards[focusedIndex].click();
  }
});

 


   document.addEventListener('DOMContentLoaded', () => {
    const filterSelect = document.getElementById('filterSelect');
    const video = document.getElementById('video');

    filterSelect.addEventListener('change', () => {
      const filterValue = filterSelect.value;
      video.style.filter = filterValue === 'none' ? 'none' : filterValue;
    });

    // Set default filter
    video.style.filter = 'none';
  });
 
function setupQualityControls(player) {
  const qualityMenu = document.getElementById('qualityMenu');
  const qualityArrow = document.getElementById('qualityArrow');
  const qualityToggle = document.querySelector('#qualityOptions > div');

  const speedMenu = document.getElementById('speedMenu');
  const speedArrow = document.getElementById('speedArrow');
  const speedToggle = document.getElementById('speedToggle');

  const settingsDropdown = document.getElementById('settingsDropdown');
  const settingsBtn = document.getElementById('settingsBtn');
  const gearWrapper = document.getElementById('gearWrapper');

  const video = document.querySelector('video');


  // ========== SETTINGS BUTTON ==========
  settingsBtn.addEventListener('click', () => {
    settingsDropdown.classList.toggle('show');
  });

  // ========== QUALITY MENU ==========
  qualityToggle.addEventListener('click', () => {
    qualityMenu.classList.toggle('show');
    qualityArrow.textContent = qualityMenu.classList.contains('show') ? '▲' : '▼';
  });

  // Quality selection logic
  qualityMenu.querySelectorAll('li').forEach(li => {
    li.addEventListener('click', async () => {
      const selected = li.getAttribute('data-quality'); // "auto", "1080", etc.
      console.log('Selected quality:', selected);

      // Highlight selected
      qualityMenu.querySelectorAll('li').forEach(el => el.classList.remove('active'));
      li.classList.add('active');

      if (selected === 'auto') {
        if (player.getVariantTracks) {
          // Shaka
          player.configure({ abr: { enabled: true } });
        } else if (player.currentLevel !== undefined) {
          // HLS.js
          player.currentLevel = -1;
        }
      } else {
        const res = parseInt(selected);

        if (player.getVariantTracks) {
          // Shaka
          const tracks = player.getVariantTracks().filter(t => !t.disabled && t.height === res);
          if (tracks.length > 0) {
            await player.configure({ abr: { enabled: false } });
            await player.selectVariantTrack(tracks[0], true);
            console.log(`Switched to ${res}p`);
          } else {
            console.warn(`Resolution ${res}p not found`);
          }
        } else if (player.levels) {
          // HLS.js
          const level = player.levels.findIndex(l => l.height === res);
          if (level !== -1) {
            player.currentLevel = level;
            console.log(`Switched to ${res}p`);
          } else {
            console.warn(`Resolution ${res}p not found`);
          }
        }
      }
    });
  });

  // ========== SPEED MENU ==========
  speedToggle.addEventListener('click', () => {
    speedMenu.classList.toggle('show');
    speedArrow.textContent = speedMenu.classList.contains('show') ? '▲' : '▼';
  });

  speedMenu.querySelectorAll('li').forEach(li => {
    li.addEventListener('click', () => {
      const selectedSpeed = parseFloat(li.getAttribute('data-speed'));
      video.playbackRate = selectedSpeed;

      // Highlight selected
      speedMenu.querySelectorAll('li').forEach(el => el.classList.remove('active'));
      li.classList.add('active');

      console.log('Playback speed set to', selectedSpeed);
    });
  });

  // ========== GLOBAL CLICK HANDLER ==========
  document.addEventListener('click', (e) => {
    if (!gearWrapper.contains(e.target)) {
      qualityMenu.classList.remove('show');
      speedMenu.classList.remove('show');
      settingsDropdown.classList.remove('show');
      qualityArrow.textContent = '▼';
      speedArrow.textContent = '▼';
    }
  });
}






let lastVolume = parseFloat(localStorage.getItem('savedVolume')) || 0.5;

// Initialize volume and slider
video.volume = lastVolume;
video.muted = lastVolume === 0;
volumeSlider.value = lastVolume;
updateVolumeIcon();

// Update volume icon SVG and tooltip
function updateVolumeIcon() {
  const muted = video.muted || video.volume === 0;
  volumeBtn.title = muted ? '🔇 Muted' : '🔊 Unmuted';
  volumeBtn.innerHTML = muted
    ? `<svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" fill="none"
          viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M11 5L6 9H3v6h3l5 4V5z" />
          <line x1="16" y1="9" x2="22" y2="15" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
          <line x1="22" y1="9" x2="16" y2="15" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
        </svg>`
    : `<svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" fill="none"
          viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M11 5L6 9H3v6h3l5 4V5z" />
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
            d="M15 9a3 3 0 010 6" />
        </svg>`;
}

// Toggle mute/unmute on icon click
volumeBtn.addEventListener('click', () => {
  if (video.muted || video.volume === 0) {
    // Unmute and restore last volume
    video.muted = false;
    video.volume = lastVolume > 0 ? lastVolume : 0.5;
    volumeSlider.value = video.volume;
  } else {
    // Mute and save last volume
    lastVolume = video.volume;
    video.muted = true;
    video.volume = 0;
    volumeSlider.value = 0;
  }
  localStorage.setItem('savedVolume', video.volume);
  updateVolumeIcon();
});

// Slider changes volume
volumeSlider.addEventListener('input', (e) => {
  const vol = parseFloat(e.target.value);
  video.volume = vol;
  video.muted = vol === 0;
  if (vol > 0) lastVolume = vol;
  localStorage.setItem('savedVolume', vol);
  updateVolumeIcon();
});

// Mouse wheel scroll on slider and icon adjusts volume smoothly
[volumeSlider, volumeBtn].forEach(el => {
  el.addEventListener('wheel', (e) => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 0.05 : -0.05;
    let newVolume = Math.min(1, Math.max(0, video.volume + delta));
    video.volume = newVolume;
    video.muted = newVolume === 0;
    volumeSlider.value = newVolume;
    if (newVolume > 0) lastVolume = newVolume;
    localStorage.setItem('savedVolume', newVolume);
    updateVolumeIcon();
  }, { passive: false });
});




// ====== Double-tap fullscreen ======
let lastTap = 0;
const doubleTapDelay = 400;
videoContainer.addEventListener('click', function() {
  const currentTap = Date.now();
  if (currentTap - lastTap < doubleTapDelay) {
    toggleFullscreen();
    lastTap = 0;
  } else {
    lastTap = currentTap;
  }
});

// ====== Toggle play/pause ======
function togglePlayPause() {
  if (video.paused) {
    video.play();
    playPauseBtn.textContent = '';
  } else {
    video.pause();
    playPauseBtn.textContent = '';
  }
}
video.addEventListener('click', togglePlayPause);

playPauseBtn.addEventListener('click', async () => {
  try {
    if (video.paused || video.ended) {
      await video.play();
      playPauseBtn.textContent = '';
    } else {
      video.pause();
      playPauseBtn.textContent = '';
    }
  } catch (err) {
    console.warn('Play/pause error:', err);
  }
});

// ====== Picture-in-Picture ======
if (pipBtn) {
  pipBtn.addEventListener('click', async () => {
    try {
      if (document.pictureInPictureElement) {
        await document.exitPictureInPicture();
      } else {
        await video.requestPictureInPicture();
      }
    } catch (err) {
      console.warn('PiP error:', err);
    }
  });
}

// ====== Active channel highlight ======
function updateActiveChannel(catIndex, chIndex) {
  document.querySelectorAll('.channel').forEach(btn => btn.classList.remove('active'));
  const category = document.getElementById('channelCategories').children[catIndex];
  if (!category) return;
  const grid = category.querySelector('div');
  if (!grid) return;
  const btns = grid.children;
  for (let i = 0; i < btns.length; i++) btns[i].classList.remove('active');
  btns[chIndex].classList.add('active');
}


    // Time update for seek bar
    video.addEventListener('timeupdate', () => {
      if (!video.duration) return;
      seekBar.value = (100 / video.duration) * video.currentTime;
    });

    seekBar.addEventListener('input', () => {
  if (seekBar.disabled) return;  // no seeking on live
  video.currentTime = video.duration * (seekBar.value / 100);
});


    // Controls visibility on mouse move
    let controlTimeout;
    videoContainer.addEventListener('mousemove', () => {
      clearTimeout(controlTimeout);
      document.getElementById('videoControls').classList.remove('opacity-0');
      controlTimeout = setTimeout(() => document.getElementById('videoControls').classList.add('opacity-0'), 3000);
    });


   

(() => {
  'use strict';

  // ==========================
  // Encrypted channel URL (split in multiple chunks)
  // ==========================
  const _chunks = [
    'aHR0cHM6Ly9naXN0LmdpdGh1',
    'YnVzZXJjb250ZW50LmNvbS9NYW5',
    'vbmdHdWFyZFZwbVYyLzNiZjcyYzRi',
    'MGYyZGRkNDRiZjQzMzEwMjU0OGNh',
    'OGI0L3Jhdy9kNzczY2MyNjViYjBh',
    'ODIyZTUwZDgzYzJhZGIzMmNkZGU4',
    'Mzg2Zjk0L2NhdGVnb3J5Y2hhbm5lbC5qc29u'
  ];

  let devToolsOpen = false;
  let shadowHost, shadowRoot;

  // ==========================
  // Random ID generator
  // ==========================
  const randomID = (len=8) => 'el_' + Math.random().toString(36).substring(2,2+len);

  // ==========================
  // Shadow DOM for sensitive content (hidden)
  // ==========================
  const createSensitiveContent = (data) => {
    shadowHost = document.createElement('div');
    shadowHost.style.display = 'none'; // fully invisible
    shadowHost.id = randomID();
    shadowRoot = shadowHost.attachShadow({ mode: 'closed' });
    const sensitive = document.createElement('div');
    sensitive.id = randomID();
    sensitive.textContent = data;
    shadowRoot.appendChild(sensitive);
    document.body.appendChild(shadowHost);
  };

  const removeSensitiveContent = () => {
    if(shadowHost){ shadowHost.remove(); shadowHost=null; shadowRoot=null; }
  };

  // ==========================
  // Get decrypted URL
  // ==========================
  const getChannelUrl = () => !devToolsOpen ? atob(_chunks.join('')) : null;

  // ==========================
  // Redirect random
  // ==========================
  const redirectRandom = () => {
    const urls=["https://www.google.com/","https://developer.mozilla.org/","https://bing.com/"];
    window.location.href = urls[Math.floor(Math.random()*urls.length)];
  };

  // ==========================
  // DevTools detection
  // ==========================
  const detectDevTools = () => {
    const wDiff = Math.abs(window.outerWidth - window.innerWidth);
    const hDiff = Math.abs(window.outerHeight - window.innerHeight);
    if((wDiff>200||hDiff>200) && !devToolsOpen){
      devToolsOpen=true;
      removeSensitiveContent();
      _chunks.length=0;
      redirectRandom();
    }
  };

  const detectTiming = () => {
    const start=performance.now();
    debugger;
    const delay = performance.now()-start;
    if(delay>150 && !devToolsOpen){
      devToolsOpen=true;
      removeSensitiveContent();
      _chunks.length=0;
      redirectRandom();
    }
  };

  const debuggerTrap = () => { try{ debugger; } catch{} };

  function antiTamper() {
    if (shadowContainer && !document.body.contains(shadowContainer)) {
      console.warn('⚠️ Shadow DOM removed. Sensitive data protected.');
      hideSensitiveUrl();
    }
  }

  // ==========================
  // Disable right-click & DevTools keys
  // ==========================
  document.addEventListener('contextmenu', e => { e.preventDefault(); redirectRandom(); });
  document.addEventListener('keydown', e=>{
    if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&['I','J','C','U'].includes(e.key))){ 
      e.preventDefault(); redirectRandom();
    }
  });
  document.addEventListener('selectstart', e => e.preventDefault());

  // ==========================
  // Suppress console logs
  // ==========================
  ['log','warn','error','info'].forEach(fn => console[fn]=()=>{});

  // ==========================
  // Continuous monitoring
  // ==========================
  setInterval(()=>{
    detectDevTools();
    detectTiming();
    debuggerTrap();
    console.clear();
  },500);

  // ==========================
  // Fetch channel data safely
  // ==========================
  const fetchChannelData = () => {
    const url = getChannelUrl();
    if(!url) return;
    fetch(url)
      .then(res=>res.json())
      .then(data=>{
        if(!data||!data.channels) return;
        createSensitiveContent(JSON.stringify(data.channels)); // hidden
        if(window.initializePlayer) window.initializePlayer(data.channels);
      })
      .catch(()=>{});
  };

  // ==========================
  // Initialize page
  // ==========================
  window.addEventListener('load', ()=>{
    setTimeout(fetchChannelData,200);
  });

})();







   function updateDateTime() {
  const now = new Date();
  const formatted = now.toLocaleString('en-US', {
    weekday: 'short', day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).replace(',', ' –');

  const html = formatted.replace(/\d+/g, (match) => `<span class="number">${match}</span>`);
  document.getElementById('datetime').innerHTML = html;
}

setInterval(updateDateTime, 1000);
updateDateTime();



 

document.addEventListener('DOMContentLoaded', () => {
  const settingsBtn = document.getElementById('settingsBtn');
  const settingsDropdown = document.getElementById('settingsDropdown');
  const openQualityModalBtn = document.getElementById('openQualityModalBtn');
  const openSpeedModalBtn = document.getElementById('openSpeedModalBtn');
  const qualityModal = document.getElementById('qualityModal');
  const speedModal = document.getElementById('speedModal');
  const closeQualityModalBtn = document.getElementById('closeQualityModal');
  const closeSpeedModalBtn = document.getElementById('closeSpeedModal');
  const qualityList = document.getElementById('qualityList');
  const speedList = document.getElementById('speedList');
  const video = document.querySelector('video');

  let player = window.shakaPlayerInstance;
  let selectedQuality = 'auto';
  let selectedSpeed = '1';

  // Helper: Decide quality by bandwidth
  function chooseQualityFromBandwidth(bandwidth) {
    if (bandwidth < 1.5) return 240;
    if (bandwidth < 3) return 360;
    if (bandwidth < 6) return 480;
    if (bandwidth < 10) return 720;
    return 1080;
  }

  // Update UI for current quality display
  function updateCurrentQualityDisplay() {
    const currentQualityDiv = document.getElementById('currentQualityDisplay');
    if (!player || !player.getVariantTracks) {
      currentQualityDiv.textContent = 'Current: Unknown';
      return;
    }

    const active = player.getVariantTracks().find(t => t.active);
    if (active) {
      currentQualityDiv.textContent = `Current: ${active.height}p @ ${active.frameRate}fps`;
      selectedQuality = String(active.height);
    } else {
      currentQualityDiv.textContent = 'Current: Auto';
      selectedQuality = 'auto';
    }

    updateSelectedQualityUI();
  }

  function updateSelectedQualityUI() {
    [...qualityList.children].forEach(li => {
      const isSelected = li.dataset.quality === selectedQuality;
      li.classList.toggle('text-cyan-300', isSelected);
      li.classList.toggle('font-semibold', isSelected);
      li.querySelector('.checkmark')?.classList.toggle('hidden', !isSelected);
    });
  }

  function updateSpeedCheckmarks() {
    [...speedList.children].forEach(li => {
      li.querySelector('.checkmark')?.classList.toggle('hidden', li.dataset.speed !== selectedSpeed);
    });
  }

  // Build quality menu dynamically
  function populateQualityList() {
    qualityList.innerHTML = '';

    const autoLi = document.createElement('li');
    autoLi.dataset.quality = 'auto';
    autoLi.className = 'cursor-pointer hover:text-cyan-300 px-2 py-1 rounded flex justify-between items-center';
    autoLi.textContent = 'Auto';
    autoLi.innerHTML += `<span class="checkmark hidden">✔️</span>`;
    qualityList.appendChild(autoLi);

    if (!player || !player.getVariantTracks) return;

    const tracks = player.getVariantTracks()
      .filter(t => t.type === 'video')
      .sort((a, b) => b.height - a.height);

    const added = new Set();
    tracks.forEach(track => {
      if (added.has(track.height)) return;
      added.add(track.height);

      const li = document.createElement('li');
      li.dataset.quality = track.height.toString();
      li.className = 'cursor-pointer hover:text-cyan-300 px-2 py-1 rounded flex justify-between items-center';
      li.textContent = `${track.height}p`;
      if (track.frameRate > 30) li.textContent += ` (${track.frameRate}fps)`;
      li.innerHTML += `<span class="checkmark hidden">✔️</span>`;
      qualityList.appendChild(li);
    });

    // Hide quality modal button if only "auto" is present
    if (qualityList.children.length <= 1) {
      openQualityModalBtn.style.display = 'none';
    } else {
      openQualityModalBtn.style.display = 'block';
    }

    updateSelectedQualityUI();
  }

  function switchToAutoQuality() {
    player.configure({ abr: { enabled: true } });
    console.log('🔁 Auto quality enabled');
    updateSelectedQualityUI();
  }

  function switchToManualQuality(height) {
    player.configure({ abr: { enabled: false } });
    const tracks = player.getVariantTracks();
    let candidates = tracks.filter(t => t.height === height);

    if (!candidates.length) {
      candidates = tracks.filter(t => Math.abs(t.height - height) <= 50);
    }

    if (candidates.length) {
      candidates.sort((a, b) => b.bandwidth - a.bandwidth);
      const selected = candidates[0];
      player.selectVariantTrack(selected, true);
      player.getMediaElement().currentTime += 0.05;
      player.getMediaElement().play();
      console.log(`🎯 Switched to ${selected.height}p`);
    } else {
      console.warn('⚠️ No close quality match, fallback to auto');
      switchToAutoQuality();
    }
    updateSelectedQualityUI();
  }

  // One clean event listener for quality changes
  qualityList.addEventListener('click', e => {
    const li = e.target.closest('li');
    if (!li) return;

    const quality = li.dataset.quality;
    if (quality === 'auto') {
      switchToAutoQuality();
    } else {
      switchToManualQuality(parseInt(quality, 10));
    }
  });


  // Gear dropdown toggle
document.getElementById('settingsBtn').addEventListener('click', () => {
  const panel = document.getElementById('settingsDropdown');
  panel.classList.toggle('hidden');
});

// Hide on outside click
document.addEventListener('click', (e) => {
  const clickedInsideSettings = gearWrapper.contains(e.target);
  const clickedInsideQuality = qualityMenu.contains(e.target);
  const clickedQualityTrigger = qualityOptionsTrigger.contains(e.target);

  // If clicked outside settings + outside quality menu + not the quality trigger itself
  if (!clickedInsideSettings && !clickedInsideQuality && !clickedQualityTrigger) {
    settingsDropdown.classList.add('hidden');
    dropdownVisible = false;

    qualityMenu.classList.add('hidden');
    qualityArrow.style.transform = 'rotate(0deg)';
  }
});


// Quality dropdown toggle
function toggleQualityMenu() {
  const menu = document.getElementById('qualityMenu');
  const arrow = document.getElementById('qualityArrow');
  menu.classList.toggle('hidden');
  arrow.style.transform = menu.classList.contains('hidden') ? 'rotate(0deg)' : 'rotate(90deg)';
}

// Quality Selection with ✔️ check
document.querySelectorAll('#qualityMenu li').forEach(item => {
  item.addEventListener('click', () => {
    const selected = item.dataset.quality;

    document.querySelectorAll('#qualityMenu li').forEach(li => li.innerHTML = li.textContent); // Clear ✔️
    item.innerHTML = '✔️ ' + item.textContent;

    if (currentFormat === 'dash') {
      player.configure({ abr: { enabled: selected === 'auto' } });
      const tracks = player.getVariantTracks().filter(t => t.type === 'video');
      let matchTrack = null;

      if (selected !== 'auto') {
        if (selected === '720-low') {
          matchTrack = tracks.find(t => t.height === 720 && t.frameRate < 30);
        } else {
          matchTrack = tracks.find(t => t.height == selected);
        }
        if (matchTrack) player.selectVariantTrack(matchTrack, true);
      }
    }

    if (currentFormat === 'hls' && window.hls) {
      window.hls.currentLevel = selected === 'auto' ? -1 : (() => {
        const lvl = window.hls.levels.find((l, i) => {
          if (selected === '720-low') return l.height === 720 && parseFloat(l.attrs?.['FRAME-RATE'] || 60) <= 30;
          return l.height == selected;
        });
        return lvl ? window.hls.levels.indexOf(lvl) : -1;
      })();
    }

    // Close quality menu
    document.getElementById('qualityMenu').classList.add('hidden');
    document.getElementById('qualityArrow').style.transform = 'rotate(0deg)';
  });
});


qualityToggle.addEventListener('click', e => {
  e.stopPropagation();
  const isShown = qualityMenu.classList.toggle('show');
  qualityArrow.style.transform = isShown ? 'rotate(90deg)' : 'rotate(0deg)';
});





  // Volume restore (existing code)
  localStorage.setItem('savedVolume', video.volume);
  const savedVolume = parseFloat(localStorage.getItem('savedVolume')) || 1;
  if (!isNaN(savedVolume)) {
    video.volume = savedVolume;
    video.muted = savedVolume === 0;
    volumeSlider.value = savedVolume;
    updateVolumeIcon();
  } else {
    video.volume = 1;
    video.muted = false;
    volumeSlider.value = 1;
  }
 

  // Speed controls
  speedList.addEventListener('click', e => {
    const li = e.target.closest('li');
    if (!li) return;
    selectedSpeed = li.dataset.speed;
    updateSpeedCheckmarks();
    if (video) video.playbackRate = parseFloat(selectedSpeed);
  });

  // Settings toggle
  settingsBtn.addEventListener('click', () => {
    settingsDropdown.classList.toggle('hidden');
  });

  openQualityModalBtn.addEventListener('click', () => {
    qualityModal.classList.remove('hidden');
    settingsDropdown.classList.add('hidden');
    updateCurrentQualityDisplay();
  });

  openSpeedModalBtn.addEventListener('click', () => {
    speedModal.classList.remove('hidden');
    settingsDropdown.classList.add('hidden');
    updateSpeedCheckmarks();
  });

  closeQualityModalBtn.addEventListener('click', () => {
    qualityModal.classList.add('hidden');
  });

  closeSpeedModalBtn.addEventListener('click', () => {
    speedModal.classList.add('hidden');
  });

  document.addEventListener('click', e => {
    if (
      !settingsDropdown.contains(e.target) &&
      !settingsBtn.contains(e.target) &&
      !qualityModal.contains(e.target) &&
      !speedModal.contains(e.target)
    ) {
      settingsDropdown.classList.add('hidden');
      qualityModal.classList.add('hidden');
      speedModal.classList.add('hidden');
    }
  });

  setInterval(() => {
    if (!qualityModal.classList.contains('hidden')) {
      updateCurrentQualityDisplay();
    }
  }, 2000);
});

// Called after manifest is loaded
async function onChannelChange(newIndex) {
  const url = channelList[newIndex].url;
  const player = window.shakaPlayerInstance;

  try {
    await player.load(url);
    console.log('✅ Manifest loaded:', url);

    populateQualityList();

    // Auto quality detection by bandwidth
    const stats = player.getStats();
    const bandwidth = stats.estimatedBandwidth / 1_000_000;
    const bestQuality = chooseQualityFromBandwidth(bandwidth);
    switchToManualQuality(bestQuality);

    retryCount = 0;
    const media = player.getMediaElement();
    media.play().catch(() => {});
  } catch (err) {
    console.error('❌ Error loading channel:', err);
  }
}



const settings = {
  lang: 'en-US',
  volume: 9,
  use24Hour: true,
  speakEveryHour: true,
};

function numberToEnglish(num) {
  const basic = [
    "zero", "one", "two", "three", "four", "five",
    "six", "seven", "eight", "nine", "ten", "eleven",
    "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
    "seventeen", "eighteen", "nineteen", "twenty"
  ];

  const tens = ["", "", "twenty", "thirty", "forty", "fifty"];

  if (num <= 20) return basic[num];
  const tenPart = Math.floor(num / 10);
  const onePart = num % 10;

  return onePart === 0
    ? tens[tenPart]
    : `${tens[tenPart]}-${basic[onePart]}`;
}

function speakTime() {
  const now = new Date();
  let hour = now.getHours();     // 0–23
  const minute = now.getMinutes();

  const hourText = numberToEnglish(hour);
  const minuteText = minute === 0 ? "o'clock" : numberToEnglish(minute);

  const fullText = `The time is ${hourText} ${minuteText}`;

  const utter = new SpeechSynthesisUtterance(fullText);
  utter.lang = settings?.lang || 'en-US';
  utter.rate = 1;
  utter.pitch = 1;
  utter.volume = settings?.volume ?? 1;

  speechSynthesis.cancel();
  speechSynthesis.speak(utter);
}

// Speak every top of the hour
setInterval(() => {
  const now = new Date();
  if (now.getMinutes() === 0 && now.getSeconds() === 0 && settings.speakEveryHour) {
    speakTime();
  }
}, 1000);

// Optional: Speak immediately if loaded at hour mark
window.addEventListener('load', () => {
  const now = new Date();
  if (now.getMinutes() === 0 && settings.speakEveryHour) {
    speakTime();
  }
});

// Test key
document.addEventListener("keydown", (e) => {
  if (e.key === "T") speakTime(); // Press "T" to test
});





  function applyVideoFilter(value) {
    const video = document.getElementById('myVideo');
    if (value === 'none') {
      video.style.filter = 'none';
    } else {
      video.style.filter = value;
    }
  }
  // Initialize with no filter
  applyVideoFilter('none');





const stations = [
  {freq:"87.5", name:"Republika FM1", logo:"https://static.mytuner.mobi/media/tvos_radios/fuyfjcn4gqee.png", url:"https://stream.zeno.fm/qnt98p5m108uv"},
  {freq:"89.1", name:"AWR Manila", logo:"https://static.mytuner.mobi/media/tvos_radios/983/awr-manila-891.ab9269f0.png", url:"http://192.53.113.120:8000/stream?type=.mp3"},
  {freq:"89.9", name:"Magic", logo:"https://static.mytuner.mobi/media/tvos_radios/216/dwtm-magic-899-fm.dd9f5d41.png", url:"https://stream.zeno.fm/sh37pvfd938uv"},
  {freq:"90.7", name:"Love Radio", logo:"https://static.mytuner.mobi/media/tvos_radios/141/dzmb-love-radio-907-fm.fd6dd832.png", url:"https://azura.loveradio.com.ph/listen/love_radio_manila/radio.mp3"},
  {freq:"91.5", name:"Win Radio", logo:"https://onlineradio.ph/uploads/img/91-5-win-radio-manila.jpg", url:"https://stream.zeno.fm/nz4ydgnu6hhvv"},
  {freq:"92.3", name:"FM RADIO Manila", logo:"https://static.mytuner.mobi/media/tvos_radios/113/fm-radio-philippines.60a60500.jpg", url:"http://us1.amfmph.com:8872/stream?type=.aac"},
  {freq:"93.1", name:"Monster Radio RX", logo:"https://static.mytuner.mobi/media/tvos_radios/209/monster-radio-rx-931-fm.bd515dec.png", url:"https://in-icecast.eradioportal.com:8443/monsterrrx"},
  {freq:"95.5", name:"Eagle FM", logo:"https://static.mytuner.mobi/media/tvos_radios/550/eagle-fm-955.31726a37.jpg", url:"http://n0c.radiojar.com/yus0r2bghd3vv?rj-ttl=5&rj-tok=AAABl4NB7pwAuUwQgelXY74u7w"},
  {freq:"96.3", name:"Easy Rock", logo:"https://static.mytuner.mobi/media/tvos_radios/138/dwrk-963-easy-rock.c2c03660.png", url:"https://azura.easyrock.com.ph/listen/easy_rock_manila/radio.mp3"},
  {freq:"97.9", name:"Home Radio", logo:"https://static.mytuner.mobi/media/tvos_radios/3fFrky9eJE.jpg", url:"https://hrmanila.radioca.st/stream"},
  {freq:"98.7", name:"The Master's Touch", logo:"https://static.mytuner.mobi/media/tvos_radios/673/dzfe-the-masters-touch-987-fm.d089acb9.jpg", url:"http://sg-icecast.eradioportal.com:8000/febc_dzfe"},
  {freq:"101.1", name:"Yes FM", logo:"https://static.mytuner.mobi/media/tvos_radios/211/yes-fm-manila-1011.3596a020.png", url:"https://azura.yesfm.com.ph/listen/yes_fm_manila/radio.mp3"},
  {freq:"100.3", name:"RJ FM", logo:"https://cdn-profiles.tunein.com/s120158/images/logog.png?t=162748", url:"https://tls.radyoph.com/secure.php?token=e65da9db216c01cc4bb7de86cdafc78f"},
  {freq:"102.7", name:"Star FM", logo:"https://static.mytuner.mobi/media/tvos_radios/848/star-fm-manila.c6a245b5.png", url:"https://stream.zeno.fm/69b1kf7q0y5tv"},
  {freq:"103.5", name:"All Radio", logo:"https://static.mytuner.mobi/media/tvos_radios/224/1035-k-lite.e3e0d2a2.png", url:"http://103.36.17.18:8000/stream"},
  {freq:"104.3", name:"Capital FM2", logo:"https://static.mytuner.mobi/media/tvos_radios/252/dwft-fm2-1043.4099fc68.png", url:"http://122.53.138.32:8000/dwbr.mp3"},
  {freq:"106.7", name:"Energy FM", logo:"https://static.mytuner.mobi/media/tvos_radios/PG5RgCjKLe.png", url:"http://ph-icecast.eradioportal.com:8000/energyfm_manila"}
];

// Populate station list
const stationList = document.getElementById("stationList");
stations.forEach((st,i)=>{
  const li = document.createElement("li");
  li.innerHTML = `<img src="${st.logo}" alt="${st.name}"><span>${st.freq} ${st.name}</span>`;
  li.addEventListener("click", ()=>{
    audio.src = st.url;
    audio.play();
    showTooltip(st.name);
    radioPanel.classList.remove("open");
  });
  stationList.appendChild(li);
});

const radioBtn = document.getElementById("radioBtn");
const playIcon = document.getElementById("playIcon");
const radioPanel = document.getElementById("radioPanel");
const audio = document.getElementById("audio");
const closeBtn = document.getElementById("closeBtn");
const tooltip = document.getElementById("tooltip");



// Tooltip
function showTooltip(text){
  tooltip.textContent = text;
  const rect = radioBtn.getBoundingClientRect();
  tooltip.style.left = rect.left + rect.width/2 - tooltip.offsetWidth/2 + "px";
  tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + "px";
  tooltip.style.opacity = 1;
  setTimeout(()=>tooltip.style.opacity=0,2000);
}

// Play/pause icon update
function updateBtnIcon(){
  if(audio.paused || audio.src===""){
    playIcon.textContent="▶️";
    radioBtn.classList.remove("playing");
  } else {
    playIcon.textContent="⏸️";
    radioBtn.classList.add("playing");
  }
}
audio.addEventListener("play", ()=>{ updateBtnIcon(); });
audio.addEventListener("pause", updateBtnIcon);
audio.addEventListener("ended", updateBtnIcon);

// Button tap/hold to open panel or play
let pressTimer=null, longPress=false;
radioBtn.addEventListener("mousedown", ()=>{
  longPress=false;
  pressTimer=setTimeout(()=>{ longPress=true; radioPanel.classList.add("open"); updatePanelPosition(); },500);
});
radioBtn.addEventListener("mouseup", ()=>{
  clearTimeout(pressTimer);
  if(!longPress){ if(audio.src){ audio.paused?audio.play():audio.pause(); } else { radioPanel.classList.add("open"); updatePanelPosition(); } }
});
radioBtn.addEventListener("touchstart", e=>{ longPress=false; pressTimer=setTimeout(()=>{ longPress=true; radioPanel.classList.add("open"); updatePanelPosition(); },500); });
radioBtn.addEventListener("touchend", e=>{ clearTimeout(pressTimer); if(!longPress){ if(audio.src){ audio.paused?audio.play():audio.pause(); } else { radioPanel.classList.add("open"); updatePanelPosition(); } } });

// Close panel
closeBtn.addEventListener("click", ()=>{ radioPanel.classList.remove("open"); });

// Close panel when clicking outside
document.addEventListener("click", function(e){
  if(radioPanel.classList.contains("open")){
    if(!radioPanel.contains(e.target) && e.target !== radioBtn){
      radioPanel.classList.remove("open");
    }
  }
});

// Panel docking
let panelSide="right";
function updatePanelPosition(){
  const btnRect = radioBtn.getBoundingClientRect();
  const panelWidth = radioPanel.offsetWidth;
  const vw = window.innerWidth;
  let top = btnRect.top + btnRect.height/2 - radioPanel.offsetHeight/2;
  if(top<10) top=10;
  if(top+radioPanel.offsetHeight>window.innerHeight-10) top=window.innerHeight-radioPanel.offsetHeight-10;
  if(btnRect.left>vw/2){ panelSide="left"; radioPanel.style.left=(btnRect.left-panelWidth-10)+"px"; radioPanel.style.transform="translateX(10%)"; }
  else { panelSide="right"; radioPanel.style.left=(btnRect.right+10)+"px"; radioPanel.style.transform="translateX(-10%)"; }
  radioPanel.style.top=top+"px";
}

// Draggable button
let offsetX=0, offsetY=0, isDown=false;
function startDrag(x,y){ isDown=true; offsetX=x-radioBtn.offsetLeft; offsetY=y-radioBtn.offsetTop; }
function moveDrag(x,y){ if(!isDown) return; const maxX=window.innerWidth-radioBtn.offsetWidth; const maxY=window.innerHeight-radioBtn.offsetHeight; let newX=x-offsetX, newY=y-offsetY; if(newX<0)newX=0; if(newY<0)newY=0; if(newX>maxX)newX=maxX; if(newY>maxY)newY=maxY; radioBtn.style.left=newX+"px"; radioBtn.style.top=newY+"px"; radioBtn.style.bottom="auto"; radioBtn.style.right="auto"; if(radioPanel.classList.contains("open")) updatePanelPosition(); }
function endDrag(){ isDown=false; }
radioBtn.addEventListener("mousedown", e=>startDrag(e.clientX,e.clientY));
document.addEventListener("mousemove", e=>moveDrag(e.clientX,e.clientY));
document.addEventListener("mouseup", endDrag);
radioBtn.addEventListener("touchstart", e=>startDrag(e.touches[0].clientX,e.touches[0].clientY));
document.addEventListener("touchmove", e=>{ if(!isDown)return; moveDrag(e.touches[0].clientX,e.touches[0].clientY); });
document.addEventListener("touchend", endDrag);

window.addEventListener("resize", ()=>{ if(radioPanel.classList.contains("open")) updatePanelPosition(); });



async function loginUser() {
  const codeInput = document.getElementById("accessCode");
  const msg = document.getElementById("loginMsg");
  msg.textContent = "";

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ accessCode: codeInput.value })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Login failed");

    document.getElementById("loginSection").style.display = "none";
    document.getElementById("channelsSection").style.display = "block";
    loadChannels();
  } catch (err) {
    msg.textContent = err.message;
  }
}

async function logoutUser() {
  await fetch("/api/logout", { method: "POST", credentials: "include" });
  document.getElementById("channelsSection").style.display = "none";
  document.getElementById("loginSection").style.display = "block";
}

async function loadChannels() {
  const list = document.getElementById("channelList");
  list.innerHTML = "<p>Loading...</p>";

  try {
    const res = await fetch("/api/channels", { credentials: "include" });
    if (!res.ok) {
      if (res.status === 401) {
        logoutUser();
        alert("Session expired. Please log in again.");
        return;
      }
      throw new Error("Failed to load channels");
    }

    const channels = await res.json();
    list.innerHTML = "";

    channels.forEach((ch) => {
      const div = document.createElement("div");
      div.className = "channel-card";
      div.innerHTML = `
        <img src="${ch.logo}" alt="${ch.name}" class="channel-logo">
        <h3>${ch.name}</h3>
        <p>${ch.category}</p>
        <a href="${ch.manifestUri}" target="_blank" class="watch-btn">▶ Watch</a>
      `;
      list.appendChild(div);
    });
  } catch (err) {
    list.innerHTML = `<p>Error: ${err.message}</p>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("loginBtn").addEventListener("click", loginUser);
  document.getElementById("logoutBtn").addEventListener("click", logoutUser);
});
