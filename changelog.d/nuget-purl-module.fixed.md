- A NuGet dependency's module is its package id (`pkg/appreach.PurlToModule`),
  and its chain frames read `pkg:nuget/<id>@<version>` instead of a purl
  prefixed twice (`pkg:nuget/pkg:nuget%2F<id>@<version>`).
