{{/* Expand the name of the chart. */}}
{{- define "qeet-id.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "qeet-id.fullname" -}}
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

{{- define "qeet-id.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "qeet-id.labels" -}}
helm.sh/chart: {{ include "qeet-id.chart" . }}
{{ include "qeet-id.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "qeet-id.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qeet-id.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "qeet-id.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "qeet-id.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The Secret name holding sensitive env (existing, external, or chart-managed). */}}
{{- define "qeet-id.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "qeet-id.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Resolved app/migrate image refs (tag defaults to appVersion). */}}
{{- define "qeet-id.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- define "qeet-id.migrateImage" -}}
{{- printf "%s:%s" .Values.migrate.image.repository (default .Chart.AppVersion .Values.migrate.image.tag) -}}
{{- end -}}
