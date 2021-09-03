-- [origin]

select
	o_orderpriority,
	count(*) as order_count
from
	orders
where
	cast(o_orderdate as Date) >= date '1995-01-01'
	and cast(o_orderdate as Date) < date '1995-01-01' + interval '3' month
	and exists (
		select
			*
		from
			lineitem
		where
			l_orderkey = o_orderkey
			and l_commitdate < l_receiptdate
	)
group by
	o_orderpriority
order by
	o_orderpriority 


  
-- [default] decorrelate manually


select
	o_orderpriority,
	count(*) as order_count
from
    (
        select
            l_orderkey,
            o_orderpriority
        from
            lineitem
            left join orders on l_orderkey = o_orderkey
        where
            cast(o_orderdate as Date) >= date '1995-01-01'
			and cast(o_orderdate as Date) < date '1995-01-01' + interval '3' month
            and l_commitdate < l_receiptdate
        group by
            l_orderkey,
            o_orderpriority
    ) t
group by
	t.o_orderpriority
order by
	t.o_orderpriority 
