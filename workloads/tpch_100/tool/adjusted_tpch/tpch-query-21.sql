-- [origin]

select
	s_name,
	count(*) as numwait
from
	supplier,
	lineitem l1,
	orders,
	nation
where
	s_suppkey = l1.l_suppkey
	and o_orderkey = l1.l_orderkey
	and o_orderstatus = 'F'
	and l1.l_receiptdate > l1.l_commitdate
	and exists (
		select
			*
		from
			lineitem l2
		where
			l2.l_orderkey = l1.l_orderkey
			and l2.l_suppkey <> l1.l_suppkey
	)
	and not exists (
		select
			*
		from
			lineitem l3
		where
			l3.l_orderkey = l1.l_orderkey
			and l3.l_suppkey <> l1.l_suppkey
			and l3.l_receiptdate > l3.l_commitdate
	)
	and s_nationkey = n_nationkey
	and n_name = 'ARGENTINA'
group by
	s_name
order by
	numwait desc,
	s_name 
limit 100 


-- [default] change join type + decorrelate manually

select s_name, count(*) as numwait
from
(
    select
        l1.l_suppkey,
        s_name,
        l1.l_orderkey
    from
        lineitem l1
        left join orders on l1.l_orderkey = o_orderkey
        left join supplier on l1.l_suppkey = s_suppkey
        left join nation on s_nationkey = n_nationkey
        inner join (
            select
                l_orderkey,
                count (distinct l_suppkey)
            from
                lineitem left join orders on l_orderkey = o_orderkey
            where
                o_orderstatus = 'F'
            group by
                l_orderkey
            having
                count (distinct l_suppkey) > 1
        ) l2 on l1.l_orderkey = l2.l_orderkey
        inner join (
            select
                l_orderkey,
                count (distinct l_suppkey)
            from
                lineitem left join orders on l_orderkey = o_orderkey
            where
                o_orderstatus = 'F'
                and l_receiptdate > l_commitdate
            group by
                l_orderkey
            having
                count (distinct l_suppkey) = 1
        ) l3 on l1.l_orderkey = l3.l_orderkey
    where
        o_orderstatus = 'F'
        and l_receiptdate > l_commitdate
        and n_name = 'ARGENTINA'
    group by
        l1.l_suppkey,
        s_name,
        l1.l_orderkey
)
group by
    s_name
order by
    numwait desc,
    s_name
limit 100


