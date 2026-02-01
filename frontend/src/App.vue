<template>
  <div class="wrap">
    <div class="card">
      <div class="top">
        <h1>PhishXAI</h1>
        
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
        <textarea
          v-model="input"
          :placeholder="placeholder"
          rows="8"
        ></textarea>

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
              Risk: <b>{{ data.result.risk }}</b> · Confidence: <b>{{ data.result.confidence }}</b>
            </div>
          </div>
        </div>

        <div class="why">
          <h3>Why this was flagged</h3>
          <ul>
            <li v-for="(r, i) in data.result.reasons" :key="i">{{ r }}</li>
          </ul>
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
  font-weight: 700;
  cursor: pointer;
}
.btn:disabled { opacity: .6; cursor: not-allowed; }

.error { margin-top: 10px; color: #f87171; }

.resultHead { display:flex; justify-content: space-between; align-items: flex-start; }
.verdict { font-size: 26px; font-weight: 800; margin: 4px 0 6px; }
.good { color: #22c55e; }
.warn { color: #f59e0b; }
.bad  { color: #ef4444; }

.why h3 { margin: 14px 0 8px; font-size: 15px; }
.why ul { margin: 0; padding-left: 18px; }
.why li { margin: 6px 0; color: #e5e7eb; }

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
