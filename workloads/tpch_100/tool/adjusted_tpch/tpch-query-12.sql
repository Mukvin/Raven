-- [origin]

select
	l_shipmode,
	sum(case
		when o_orderpriority = '1-URGENT'
			or o_orderpriority = '2-HIGH'
			then 1
		else 0
	end) as high_line_count,
	sum(case
		when o_orderpriority <> '1-URGENT'
			and o_orderpriority <> '2-HIGH'
			then 1
		else 0
	end) as low_line_count
from
	orders,
	lineitem
where
	o_orderkey = l_orderkey
	and l_shipmode in ('SHIP', 'AIR')
	and l_commitdate < l_receiptdate
	and l_shipdate < l_commitdate
	and cast(l_receiptdate as Date) >= date '1995-01-01'
	and cast(l_receiptdate as Date) < date '1995-01-01' + interval '1' year
group by
	l_shipmode
order by
	l_shipmode 
  
-- [default] change join type

select
	l_shipmode,
	sum(case
		when o_orderpriority = '1-URGENT'
			or o_orderpriority = '2-HIGH'
			then 1
		else 0
	end) as high_line_count,
	sum(case
		when o_orderpriority <> '1-URGENT'
			and o_orderpriority <> '2-HIGH'
			then 1
		else 0
	end) as low_line_count
from
	lineitem left join orders on l_orderkey = o_orderkey
where
	l_shipmode in ('SHIP', 'AIR')
	and l_commitdate < l_receiptdate
	and l_shipdate < l_commitdate
	and cast(l_receiptdate as Date) >= date '1995-01-01'
	and cast(l_receiptdate as Date) < date '1995-01-01' + interval '1' year
group by
	l_shipmode
order by
	l_shipmode 
  
