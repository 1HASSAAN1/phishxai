<template>
  <div class="wrap">
    <div class="card">
      <div class="top">
        <h1>PhishXAI</h1>
        <p class="sub">Multi-channel phishing detection with explainable AI (XAI)</p>
      </div>

      <div class="section">
        <h2>Select Message Type</h2>
        <p class="muted">Choose the channel to ensure accurate analysis.</p>

        <label>Channel</label>
        <select v-model="channel">
          <option value="email">Email</option>
          <option value="sms">SMS / Message</option>
          <option value="url">URL / Website</option>
        </select>
      </div>

      <div class="section">
        <h2>Provide Content</h2>
        <p class="muted">Paste content below (file upload comes later).</p>

        <label>{{ inputLabel }}</label>
        <textarea v-model="input" :placeholder="placeholder" rows="8"></textarea>

        <button class="btn" :disabled="loading || !input.trim()" @click="analyze">
          {{ loading ? "Analyzing..." : "Analyze" }}
        </button>

        <p v-if="error" class="error">{{ error }}</p>
      </div>

      <div v-if="data" class="section result">
        <div class="resultHead">
          <div>
            <div class="muted small">Result</div>
            <div class="verdict" :class="verdictClass">{{ data.result.verdict }}</div>
            <div class="muted">
              Risk: <b>{{ fmt(data.result.risk) }}</b> · Confidence: <b>{{ fmt(data.result.confidence) }}</b>
            </div>
            <div class="muted small" v-if="data.result?.probabilities">
              P(safe): <b>{{ fmt(data.result.probabilities.safe) }}</b> ·
              P(phish): <b>{{ fmt(data.result.probabilities.phish) }}</b>
            </div>
          </div>

          <button class="btn secondary" @click="copyJson">
            Copy JSON
          </button>
        </div>

        <div class="why">
          <h3>Why this was flagged</h3>
          <ul>
            <li v-for="(r, i) in data.result.reasons" :key="i">{{ r }}</li>
          </ul>
        </div>

        <!-- XAI SECTION -->
        <div v-if="hasXai" class="xai">
          <h3>Explainable AI (XAI)</h3>
          <p class="muted">
            These tokens contributed most to the model’s prediction (local explanation).
          </p>

          <div class="xaiGrid">
            <!-- SHAP -->
            <div class="xaiBox" v-if="shapTokens?.length">
              <div class="xaiTitle">
                <span>SHAP</span>
                <span class="pill">Top tokens</span>
              </div>

              <ul class="tokenList">
                <li v-for="(t, i) in shapTokens" :key="'s'+i" class="tokenRow">
                  <span class="token">{{ t.token }}</span>
                  <span class="score">{{ fmt(t.contribution) }}</span>
                </li>
              </ul>

              <p class="muted small note">
                Higher positive contribution pushes the prediction towards phishing.
              </p>
            </div>

            <!-- LIME -->
            <div class="xaiBox" v-if="limeTokens?.length">
              <div class="xaiTitle">
                <span>LIME</span>
                <span class="pill">Top features</span>
              </div>

              <ul class="tokenList">
                <li v-for="(t, i) in limeTokens" :key="'l'+i" class="tokenRow">
                  <span class="token">{{ t.token }}</span>
                  <span class="score">{{ fmt(t.weight) }}</span>
                </li>
              </ul>

              <p class="muted small note">
                Positive weight typically supports phishing, negative supports safe.
              </p>
            </div>

            <!-- If XAI exists but tokens missing -->
            <div class="xaiBox" v-if="hasXai && !shapTokens?.length && !limeTokens?.length">
              <div class="xaiTitle">
                <span>XAI</span>
                <span class="pill">Not available</span>
              </div>
              <p class="muted">
                The backend did not return token explanations. This can happen if SHAP/LIME
                is not installed or explanation failed.
              </p>
              <p class="muted small">
                Available: SHAP={{ data.xai?.available?.shap ? "Yes" : "No" }},
                LIME={{ data.xai?.available?.lime ? "Yes" : "No" }}
              </p>
              <p class="muted small" v-if="data.xai?.warning">
                Warning: {{ data.xai.warning }}
              </p>
            </div>
          </div>
        </div>

        <details class="raw">
          <summary>Raw JSON</summary>
          <pre>{{ JSON.stringify(data, null, 2) }}</pre>
        </details>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from "vue";

const channel = ref("email");
const input = ref("");
const loading = ref(false);
const error = ref("");
const data = ref(null);

const inputLabel = computed(() => {
  if (channel.value === "url") return "URL";
  if (channel.value === "sms") return "Message text";
  return "Email body";
});

const placeholder = computed(() => {
  if (channel.value === "url") return "https://example.com/login";
  if (channel.value === "sms") return "Paste SMS text here…";
  return "Paste email content here…";
});

const verdictClass = computed(() => {
  const v = data.value?.result?.verdict || "";
  if (v.toLowerCase().includes("phish")) return "bad";
  if (v.toLowerCase().includes("susp")) return "warn";
  return "good";
});

const hasXai = computed(() => !!data.value?.xai);

const shapTokens = computed(() => data.value?.xai?.shap_top_tokens || []);
const limeTokens = computed(() => data.value?.xai?.lime_top_tokens || []);

function fmt(x) {
  if (x === null || x === undefined) return "-";
  const n = Number(x);
  if (Number.isNaN(n)) return String(x);
  // prettier for demo
  return n.toFixed(4);
}

async function analyze() {
  loading.value = true;
  error.value = "";
  data.value = null;

  try {
    const payload =
      channel.value === "url"
        ? { channel: "url", url: input.value.trim() }
        : { channel: channel.value, text: input.value };

    const res = await fetch("http://127.0.0.1:5000/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "Request failed");
    data.value = json;
  } catch (e) {
    error.value = e?.message || String(e);
  } finally {
    loading.value = false;
  }
}

async function copyJson() {
  try {
    await navigator.clipboard.writeText(JSON.stringify(data.value, null, 2));
  } catch {
    // fallback
    const el = document.createElement("textarea");
    el.value = JSON.stringify(data.value, null, 2);
    document.body.appendChild(el);
    el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
  }
}
</script>

<style>
.wrap {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  background: #0f172a;
  padding: 28px;
}
.card {
  width: 100%;
  max-width: 860px;
  background: #020617;
  border: 1px solid #1f2937;
  border-radius: 18px;
  padding: 22px;
  color: #e5e7eb;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
}
.top { margin-bottom: 14px; }
h1 { margin: 0; color: #38bdf8; }
.sub { margin: 6px 0 0 0; color: #94a3b8; }

.section {
  margin-top: 14px;
  background: #0b1220;
  border: 1px solid #334155;
  border-radius: 16px;
  padding: 16px;
}
h2 { margin: 0 0 6px 0; font-size: 16px; }
.muted { color: #94a3b8; margin: 0 0 10px 0; }
.small { font-size: 12px; }

label { display:block; font-size: 13px; color:#cbd5e1; margin: 10px 0 6px; }
select, textarea {
  width: 100%;
  background: #020617;
  border: 1px solid #334155;
  border-radius: 12px;
  color: #e5e7eb;
  padding: 10px;
  font-size: 14px;
}
textarea { resize: vertical; }

.btn {
  width: 100%;
  margin-top: 12px;
  padding: 12px;
  border: 0;
  border-radius: 12px;
  background: #2563eb;
  color: white;
  font-weight: 800;
  cursor: pointer;
}
.btn:disabled { opacity: .6; cursor: not-allowed; }
.btn.secondary {
  width: auto;
  margin-top: 0;
  padding: 10px 12px;
  background: #111827;
  border: 1px solid #334155;
  font-weight: 700;
}

.error { margin-top: 10px; color: #f87171; }

.resultHead { display:flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.verdict { font-size: 26px; font-weight: 900; margin: 4px 0 6px; }
.good { color: #22c55e; }
.warn { color: #f59e0b; }
.bad  { color: #ef4444; }

.why h3, .xai h3 { margin: 14px 0 8px; font-size: 15px; }
.why ul { margin: 0; padding-left: 18px; }
.why li { margin: 6px 0; color: #e5e7eb; }

.xaiGrid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
@media (max-width: 700px) {
  .xaiGrid { grid-template-columns: 1fr; }
}

.xaiBox {
  background: #020617;
  border: 1px solid #334155;
  border-radius: 14px;
  padding: 12px;
}
.xaiTitle {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
  font-weight: 800;
}
.pill {
  font-size: 12px;
  color: #cbd5e1;
  border: 1px solid #334155;
  padding: 4px 8px;
  border-radius: 999px;
}

.tokenList {
  list-style: none;
  padding: 0;
  margin: 0;
}
.tokenRow {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 10px;
  border: 1px solid #1f2937;
  border-radius: 10px;
  margin-bottom: 8px;
}
.token { font-weight: 700; color: #e5e7eb; }
.score { font-variant-numeric: tabular-nums; color: #93c5fd; font-weight: 800; }

.note { margin: 8px 0 0 0; }

.raw { margin-top: 12px; }
pre {
  margin-top: 8px;
  background: #020617;
  border: 1px solid #334155;
  border-radius: 12px;
  padding: 12px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
