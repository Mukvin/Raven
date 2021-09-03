-- [origin]

select
	s_name,
	s_address
from
	supplier,
	nation
where
	s_suppkey in (
		select
			ps_suppkey
		from
			partsupp
		where
			ps_partkey in (
				select
					p_partkey
				from
					part
				where
					p_name like 'hot%'
			)
			and ps_availqty > (
				select
					0.5 * sum(l_quantity)
				from
					lineitem
				where
					l_partkey = ps_partkey
					and l_suppkey = ps_suppkey
					and cast(l_shipdate as Date) >= date '1994-01-01'
					and cast(l_shipdate as Date) < date '1994-01-01' + interval '1' year
			)
	)
	and s_nationkey = n_nationkey
	and n_name = 'CHINA'
order by
	s_name 
  
-- [default] change join type + decorrelate manually (different semantic compared to origin)



select
    s_name,
    s_address
from
    partsupp
    left join supplier on ps_suppkey = s_suppkey
    inner join  (
    select l_partkey, 0.5 * sum(l_quantity) as sum_quantity, l_suppkey
    from lineitem
    left join supplier on l_suppkey = s_suppkey
    left join nation on s_nationkey = n_nationkey
    left join part on l_partkey = p_partkey
    where cast(l_shipdate as Date) >= date '1994-01-01'
					and cast(l_shipdate as Date) < date '1994-01-01' + interval '1' year
    and n_name = 'CHINA'
    and p_name like 'hot%'
    group by l_partkey, l_suppkey
) on ps_partkey = l_partkey and ps_suppkey = l_suppkey
where
    ps_availqty > sum_quantity
group by
    s_name, s_address
order by
    s_name


  
