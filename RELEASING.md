# Как выпустить релиз

Релиз выходит на каждую версию x.y.z (см. [правила в дорожной карте](docs/ROADMAP.md#правила-версий-и-релизов)).

## Шаги

1. **Все пункты версии выполнены** — отмечены `[x]` в [docs/ROADMAP.md](docs/ROADMAP.md); невыполненные перенесены в следующую версию.
2. **CI зелёный** на `main` для всех платформ.
3. **CHANGELOG.md:** переименуйте раздел «Не выпущено» в `## [X.Y.Z] — ГГГГ-ММ-ДД` и добавьте над ним новый пустой «Не выпущено». Проверьте заметки:
   ```bash
   scripts/release-notes.sh X.Y.Z
   ```
4. **Пробная сборка** (необязательно, CI сделает то же):
   ```bash
   go run github.com/goreleaser/goreleaser/v2@v2.18.2 release --snapshot --clean
   ```
5. **Коммит и тег:**
   ```bash
   git commit -am "Релиз X.Y.Z"
   git tag -a vX.Y.Z -m "zeropentime X.Y.Z"
   git push origin main vX.Y.Z
   ```
6. Workflow `release` прогоняет тесты, собирает архивы и создаёт **черновик** релиза на GitHub с заметками из CHANGELOG.md.
7. **Проверьте черновик:** архивы для всех платформ, `checksums.txt`, заметки. Скачайте архив для своей платформы и выполните `zpt version`. Опубликуйте релиз.

## Что попадает в релиз

| Архив | Содержимое | Лицензия |
|---|---|---|
| `zpt_X.Y.Z_{linux,windows}_{amd64,arm64}` | узел `zpt`, пример конфига; для Windows — `wintun.dll` и её лицензия | MPL-2.0 (`LICENSE`); Wintun — своя лицензия (`wintun-LICENSE.txt`) |
| `zpt-controller_X.Y.Z_{linux,windows}_{amd64,arm64}` | контроллер с админ-панелью | AGPL-3.0 (`LICENSE.AGPL`) |
| `checksums.txt` | SHA-256 всех архивов | — |

## Если сломался сам workflow

Если тесты прошли, а упал шаг сборки или публикации (ошибка в workflow, а не в коде), номер версии не сжигается: соберите релиз из того же тега локально и исправьте workflow отдельным коммитом.

```bash
git worktree add /tmp/rel vX.Y.Z && cd /tmp/rel
bash scripts/release-notes.sh X.Y.Z > /tmp/notes.md
GITHUB_TOKEN=$(gh auth token) go run github.com/goreleaser/goreleaser/v2@v2.18.2 release --clean --release-notes /tmp/notes.md
```

## Срочный релиз

Для исправления уязвимости или потери связи — следующий z без ожидания плановых пунктов: только исправление, запись в CHANGELOG, те же шаги.
