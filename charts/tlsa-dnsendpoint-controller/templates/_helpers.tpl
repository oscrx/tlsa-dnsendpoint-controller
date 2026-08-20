{{- define "tlsa-dnsendpoint-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tlsa-dnsendpoint-controller.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "tlsa-dnsendpoint-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tlsa-dnsendpoint-controller.labels" -}}
helm.sh/chart: {{ include "tlsa-dnsendpoint-controller.chart" . }}
{{ include "tlsa-dnsendpoint-controller.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tlsa-dnsendpoint-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tlsa-dnsendpoint-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tlsa-dnsendpoint-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tlsa-dnsendpoint-controller.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tlsa-dnsendpoint-controller.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
Fail early on configurations that would misbehave at runtime rather than
letting the user discover them from controller logs.
*/}}
{{- define "tlsa-dnsendpoint-controller.validate" -}}
{{- if and (gt (int .Values.replicaCount) 1) (not .Values.leaderElection.enabled) -}}
{{- fail "replicaCount > 1 requires leaderElection.enabled=true, otherwise every replica reconciles the same Certificates and they will contend over the same DNSEndpoint" -}}
{{- end -}}
{{- if not .Values.controller.annotationPrefix -}}
{{- fail "controller.annotationPrefix must be set to a DNS subdomain you control; it becomes part of the annotation key read from Certificates" -}}
{{- end -}}
{{- if and .Values.metrics.serviceMonitor.enabled (not .Values.metrics.enabled) -}}
{{- fail "metrics.serviceMonitor.enabled requires metrics.enabled=true" -}}
{{- end -}}
{{- end -}}
