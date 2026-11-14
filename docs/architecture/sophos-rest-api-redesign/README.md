# Sophos REST API redesign

Documentación de diseño para reemplazar la integración XML del proyecto por una implementación basada exclusivamente en Sophos Firewall REST API.

## Documentos

- [Plan técnico](./PLAN.md): decisión arquitectónica, correspondencia funcional, diseño recomendado, fases, issues, pruebas, seguridad y riesgos.
- [Referencias](./REFERENCES.md): URLs de la especificación del repositorio, documentación oficial de Sophos, SDK MCP, estándares y herramientas evaluadas.

## Estado

- **Diseño:** propuesto.
- **Implementación:** no iniciada por este documento.
- **Issues de ejecución:** todavía no creados.
- **Siguiente paso:** completar la Fase 0 del plan y registrar el inventario validado de endpoints y esquemas en `docs/API-COVERAGE.md`.

La especificación OpenAPI incluida en el repositorio es el contrato que debe auditarse en la Fase 0. Las referencias web documentan el contexto y las prácticas de implementación, pero no sustituyen la inspección del YAML versionado ni las pruebas contra el firmware de destino.
