# CloudTrail ログ分析ツール

CloudTrailのログデータからIAMユーザの稼働時間を分析し、表形式で出力するPythonスクリプトです。

## 機能

- CloudTrailログファイル（JSON形式）からIAMユーザのアクティビティを抽出
- 各ユーザの日別稼働時間を計算（最初のアクティビティから最後のアクティビティまで）
- 表、CSV、JSON形式での出力に対応
- 特定のユーザまたは全ユーザの分析が可能

## インストール

このプロジェクトはuvを使用して管理されています。

### 前提条件
- [mise](https://mise.jdx.dev/) がインストールされていること

### セットアップ
```bash
# uvをインストール（miseを使用）
mise install uv

# プロジェクトディレクトリに移動
cd cloudtrail-to-working-list

# uvで依存関係をインストール
uv sync
```

## 使用方法

### 基本的な使用方法

```bash
# 全ユーザの稼働時間を表形式で表示
uv run python cloudtrail_analyzer.py sample_cloudtrail.json

# 特定のユーザ（alice）の稼働時間を表示
uv run python cloudtrail_analyzer.py sample_cloudtrail.json -u alice

# CSV形式で出力
uv run python cloudtrail_analyzer.py sample_cloudtrail.json -f csv

# 結果をファイルに保存
uv run python cloudtrail_analyzer.py sample_cloudtrail.json -o output.csv -f csv
```

### コマンドラインオプション

- `log_path`: CloudTrailログファイルまたはディレクトリのパス（必須）
- `-u, --username`: 特定のユーザ名を指定（省略時は全ユーザ）
- `-f, --format`: 出力形式（table, csv, json）、デフォルトは table
- `-o, --output`: 出力ファイル名（省略時は標準出力）

### 入力ファイル形式

CloudTrailの標準的なJSON形式をサポートします：

```json
{
  "Records": [
    {
      "eventTime": "2025-06-30T09:15:30Z",
      "eventName": "AssumeRole",
      "eventSource": "sts.amazonaws.com",
      "userIdentity": {
        "type": "IAMUser",
        "userName": "alice"
      },
      "sourceIPAddress": "203.0.113.1"
    }
  ]
}
```

## 出力例

### 表形式
```
    ユーザ名        日付    開始時刻    終了時刻      稼働時間  アクティビティ数  最初のアクション    最後のアクション  IPアドレス
0     alice  2025-06-30   09:15:30   17:45:30  8:30:00                4    AssumeRole        PutObject  203.0.113.1
1       bob  2025-06-30   10:45:20   16:30:00  5:44:40                2  DescribeInstances  StopInstances  203.0.113.2
2   charlie  2025-06-29   08:30:15   12:15:45  3:45:30                2    CreateStack      UpdateStack  203.0.113.3
```

### 分析項目

- **ユーザ名**: IAMユーザ名
- **日付**: アクティビティがあった日付
- **開始時刻**: その日の最初のアクティビティ時刻
- **終了時刻**: その日の最後のアクティビティ時刻
- **稼働時間**: 開始時刻から終了時刻までの時間
- **アクティビティ数**: その日のAPIコール数
- **最初のアクション**: その日の最初のAPIアクション
- **最後のアクション**: その日の最後のAPIアクション
- **IPアドレス**: アクセス元IPアドレス

## 対応するユーザタイプ

- IAMUser: 通常のIAMユーザ
- AssumedRole: ロールを使用したアクセス

## サンプルデータ

`sample_cloudtrail.json` にサンプルデータが含まれています。このファイルを使用してスクリプトの動作を確認できます。

## 注意事項

- CloudTrailログは UTC タイムゾーンで記録されているため、出力時刻も UTC で表示されます
- 稼働時間は「最初のアクティビティから最後のアクティビティまでの時間」として計算されます
- 実際の作業時間とは異なる場合があります（長時間の中断がある場合など）
- 大きなログファイルを処理する場合は、メモリ使用量にご注意ください
