{{/* Expand the name of the chart. */}}
{{- define "sts-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a default fully qualified app name. */}}
{{- define "sts-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Cluster-scoped RBAC names must not collide across namespaces. */}}
{{- define "sts-operator.rbacName" -}}
{{- $name := printf "%s-%s" .Release.Namespace (include "sts-operator.fullname" .) }}
{{- if gt (len $name) 63 }}
{{- printf "%s-%s" ($name | trunc 54 | trimSuffix "-") ($name | sha256sum | trunc 8) }}
{{- else }}
{{- $name }}
{{- end }}
{{- end }}

{{/* Common labels. */}}
{{- define "sts-operator.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "sts-operator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels. */}}
{{- define "sts-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sts-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Create the name of the service account to use. */}}
{{- define "sts-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sts-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
