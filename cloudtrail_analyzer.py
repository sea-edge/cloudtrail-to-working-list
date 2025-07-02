#!/usr/bin/env python3
"""
CloudTrail ログからIAMユーザの稼働時間を分析するスクリプト

このスクリプトは以下の機能を提供します：
1. CloudTrailログファイル（JSON）の読み込み
2. 指定されたIAMユーザのアクティビティを抽出
3. ユーザの稼働時間（最初と最後のアクティビティ）を表形式で出力
"""

import json
import os
import argparse
import pandas as pd
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
import glob


class CloudTrailAnalyzer:
    def __init__(self):
        self.events = []
        
    def load_cloudtrail_logs(self, log_path: str) -> None:
        """
        CloudTrailログファイルを読み込む
        
        Args:
            log_path: ログファイルのパスまたはディレクトリパス
        """
        if os.path.isfile(log_path):
            # 単一ファイルの場合
            self._load_single_file(log_path)
        elif os.path.isdir(log_path):
            # ディレクトリの場合、JSONファイルを再帰的に検索
            json_files = glob.glob(os.path.join(log_path, "**/*.json"), recursive=True)
            for file_path in json_files:
                self._load_single_file(file_path)
        else:
            raise FileNotFoundError(f"指定されたパス '{log_path}' が見つかりません")
    
    def _load_single_file(self, file_path: str) -> None:
        """単一のJSONファイルを読み込む"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # CloudTrailログの形式に応じて処理
            if 'Records' in data:
                # 標準的なCloudTrailログ形式
                self.events.extend(data['Records'])
            elif isinstance(data, list):
                # イベントのリスト形式
                self.events.extend(data)
            else:
                # 単一イベント
                self.events.append(data)
                
            print(f"読み込み完了: {file_path} ({len(data.get('Records', [data]))} イベント)")
            
        except json.JSONDecodeError as e:
            print(f"JSONデコードエラー in {file_path}: {e}")
        except Exception as e:
            print(f"ファイル読み込みエラー in {file_path}: {e}")
    
    def extract_user_activities(self, username: Optional[str] = None, debug: bool = False) -> Dict[str, List[Dict]]:
        """
        IAMユーザのアクティビティを抽出する
        
        Args:
            username: 特定のユーザ名（指定しない場合は全ユーザ）
            debug: デバッグ情報を出力するかどうか
            
        Returns:
            ユーザ名をキーとしたアクティビティのディクショナリ
        """
        user_activities = {}
        processed_events = 0
        skipped_events = 0
        
        for event in self.events:
            processed_events += 1
            try:
                # ユーザ情報の抽出
                user_identity = event.get('userIdentity', {})
                user_type = user_identity.get('type')
                
                if debug:
                    print(f"イベント {processed_events}: {event.get('eventName')} - ユーザタイプ: {user_type}")
                
                # IAMユーザまたはAssumedRoleのみを対象とする
                if user_type not in ['IAMUser', 'AssumedRole']:
                    skipped_events += 1
                    if debug:
                        print(f"  スキップ: 対象外のユーザタイプ ({user_type})")
                    continue
                
                # ユーザ名の取得
                if user_type == 'IAMUser':
                    current_user = user_identity.get('userName')
                elif user_type == 'AssumedRole':
                    # AssumedRoleの場合、セッション名またはARNから取得
                    arn = user_identity.get('arn', '')
                    if '/assumed-role/' in arn:
                        current_user = arn.split('/')[-1]  # セッション名
                    else:
                        current_user = user_identity.get('sessionContext', {}).get('sessionIssuer', {}).get('userName')
                
                if not current_user:
                    skipped_events += 1
                    if debug:
                        print(f"  スキップ: ユーザ名が取得できません")
                    continue
                
                if debug:
                    print(f"  ユーザ名: {current_user}")
                
                # 特定のユーザが指定されている場合はフィルタリング
                if username and current_user != username:
                    skipped_events += 1
                    if debug:
                        print(f"  スキップ: 指定ユーザと異なる ({current_user} != {username})")
                    continue
                
                # イベント時刻の取得
                event_time = event.get('eventTime')
                if not event_time:
                    skipped_events += 1
                    if debug:
                        print(f"  スキップ: イベント時刻がありません")
                    continue
                
                if debug:
                    print(f"  処理: {event_time} - {event.get('eventName')}")
                
                activity = {
                    'eventTime': event_time,
                    'eventName': event.get('eventName'),
                    'eventSource': event.get('eventSource'),
                    'sourceIPAddress': event.get('sourceIPAddress'),
                    'userAgent': event.get('userAgent'),
                    'awsRegion': event.get('awsRegion'),
                    'userType': user_type
                }
                
                if current_user not in user_activities:
                    user_activities[current_user] = []
                
                user_activities[current_user].append(activity)
                
            except Exception as e:
                skipped_events += 1
                print(f"イベント処理エラー: {e}")
                if debug:
                    print(f"  エラーイベント: {event}")
                continue
        
        if debug:
            print(f"\n処理統計:")
            print(f"  総イベント数: {processed_events}")
            print(f"  処理済みイベント: {processed_events - skipped_events}")
            print(f"  スキップイベント: {skipped_events}")
            print(f"  発見ユーザ数: {len(user_activities)}")
            for user, activities in user_activities.items():
                print(f"    {user}: {len(activities)} アクティビティ")
        
        # 各ユーザのアクティビティを時刻順にソート
        for user in user_activities:
            user_activities[user].sort(key=lambda x: x['eventTime'])
        
        return user_activities
    
    def calculate_working_hours(self, user_activities: Dict[str, List[Dict]]) -> List[Dict]:
        """
        各ユーザの稼働時間を計算する
        
        Args:
            user_activities: ユーザアクティビティのディクショナリ
            
        Returns:
            稼働時間情報のリスト
        """
        working_hours = []
        
        for username, activities in user_activities.items():
            if not activities:
                continue
            
            # 最初と最後のアクティビティ
            first_activity = activities[0]
            last_activity = activities[-1]
            
            # 日付ごとにグループ化
            daily_activities = {}
            for activity in activities:
                event_time = datetime.fromisoformat(activity['eventTime'].replace('Z', '+00:00'))
                date_str = event_time.strftime('%Y-%m-%d')
                
                if date_str not in daily_activities:
                    daily_activities[date_str] = []
                daily_activities[date_str].append(activity)
            
            # 各日の稼働時間を計算
            for date_str, day_activities in daily_activities.items():
                day_activities.sort(key=lambda x: x['eventTime'])
                
                first_time = datetime.fromisoformat(day_activities[0]['eventTime'].replace('Z', '+00:00'))
                last_time = datetime.fromisoformat(day_activities[-1]['eventTime'].replace('Z', '+00:00'))
                
                working_hours.append({
                    'ユーザ名': username,
                    '日付': date_str,
                    '開始時刻': first_time.strftime('%H:%M:%S'),
                    '終了時刻': last_time.strftime('%H:%M:%S'),
                    '稼働時間 (時:分:秒)': str(last_time - first_time),
                    'アクティビティ数': len(day_activities),
                    '最初のアクション': day_activities[0]['eventName'],
                    '最後のアクション': day_activities[-1]['eventName'],
                    'IPアドレス': day_activities[0]['sourceIPAddress']
                })
        
        return working_hours
    
    def generate_report(self, working_hours: List[Dict], output_format: str = 'table') -> str:
        """
        レポートを生成する
        
        Args:
            working_hours: 稼働時間データ
            output_format: 出力形式 ('table', 'csv', 'json')
            
        Returns:
            レポート文字列
        """
        if not working_hours:
            return "稼働データが見つかりませんでした。"
        
        df = pd.DataFrame(working_hours)
        df = df.sort_values(['ユーザ名', '日付'])
        
        if output_format == 'csv':
            return df.to_csv(index=False)
        elif output_format == 'json':
            return df.to_json(orient='records', indent=2, ensure_ascii=False)
        else:
            return df.to_string(index=False)
    
    def analyze(self, log_path: str, username: Optional[str] = None, 
                output_format: str = 'table', debug: bool = False) -> str:
        """
        メイン分析関数
        
        Args:
            log_path: CloudTrailログのパス
            username: 特定のユーザ名（オプション）
            output_format: 出力形式
            debug: デバッグ情報を出力するかどうか
            
        Returns:
            分析結果
        """
        print(f"CloudTrailログを読み込み中: {log_path}")
        self.load_cloudtrail_logs(log_path)
        
        print(f"総イベント数: {len(self.events)}")
        
        print("ユーザアクティビティを抽出中...")
        user_activities = self.extract_user_activities(username, debug)
        
        if not user_activities:
            return "指定された条件に一致するユーザアクティビティが見つかりませんでした。"
        
        print(f"発見されたユーザ数: {len(user_activities)}")
        
        print("稼働時間を計算中...")
        working_hours = self.calculate_working_hours(user_activities)
        
        return self.generate_report(working_hours, output_format)


def main():
    parser = argparse.ArgumentParser(
        description='CloudTrailログからIAMユーザの稼働時間を分析します'
    )
    parser.add_argument(
        'log_path',
        help='CloudTrailログファイルまたはディレクトリのパス'
    )
    parser.add_argument(
        '-u', '--username',
        help='特定のユーザ名を指定（省略時は全ユーザ）'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['table', 'csv', 'json'],
        default='table',
        help='出力形式を指定（デフォルト: table）'
    )
    parser.add_argument(
        '-o', '--output',
        help='出力ファイル名（省略時は標準出力）'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='デバッグ情報を表示'
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = CloudTrailAnalyzer()
        result = analyzer.analyze(args.log_path, args.username, args.format, args.debug)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(result)
            print(f"結果を {args.output} に保存しました。")
        else:
            print("\n" + "="*80)
            print("IAMユーザ稼働時間分析結果")
            print("="*80)
            print(result)
            
    except Exception as e:
        print(f"エラーが発生しました: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
