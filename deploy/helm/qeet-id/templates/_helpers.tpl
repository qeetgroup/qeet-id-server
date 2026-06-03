{{- define "qeet-id.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "qeet-id.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "qeet-id.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "qeet-id.labels" -}}
app.kubernetes.io/name: {{ include "qeet-id.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "qeet-id.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qeet-id.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "qeet-id.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "qeet-id.fullname" . -}}
{{- end -}}
{{- end -}}

{{- define "qeet-id.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "qeet-id.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "qeet-id.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{- define "qeet-id.migrateImage" -}}
{{- printf "%s:%s" .Values.migrate.image.repository (.Values.migrate.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
