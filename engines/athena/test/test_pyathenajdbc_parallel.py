import time

from pyathenajdbc import connect


def test_basic():
    start = time.time()
    conn = connect(S3OutputLocation='s3://raven-olap-benchmark/athena/staging',
                   AwsRegion='us-west-2')
    print(f'it takes {time.time() - start}s to init conn')

    try:
        start = time.time()
        with conn.cursor() as cursor:
            cursor.execute("""
            SELECT count(*), month FROM "cfn-database-flights-1"."cfn-manual-table-flights-1" group by month
            """)
            print(cursor.description)
            print(cursor.fetchall())
        print(time.time() - start)
    finally:
        conn.close()


if __name__ == '__main__':
    test_basic()
