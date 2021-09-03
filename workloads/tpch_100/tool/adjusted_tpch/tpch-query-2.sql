-- [origin]


select
	s_acctbal,
	s_name,
	n_name,
	p_partkey,
	p_mfgr,
	s_address,
	s_phone,
	s_comment
from
	part,
	supplier,
	partsupp,
	nation,
	region
where
	p_partkey = ps_partkey
	and s_suppkey = ps_suppkey
	and p_size = 9
	and p_type like '%COPPER'
	and s_nationkey = n_nationkey
	and n_regionkey = r_regionkey
	and r_name = 'AMERICA'
	and ps_supplycost = (
		select
			min(ps_supplycost)
		from
			partsupp,
			supplier,
			nation,
			region
		where
			p_partkey = ps_partkey
			and s_suppkey = ps_suppkey
			and s_nationkey = n_nationkey
			and n_regionkey = r_regionkey
			and r_name = 'AMERICA'
	)
order by
	s_acctbal desc,
	n_name,
	s_name,
	p_partkey 
limit 100 


-- [default] change join type + decorrelate manually

select
	s_acctbal,
	s_name,
	n_name,
	p_partkey,
	p_mfgr,
	s_address,
	s_phone,
	s_comment
from
	partsupp
	left join part on p_partkey = ps_partkey
	left join supplier on s_suppkey = ps_suppkey
	left join nation on s_nationkey = n_nationkey
	left join region on n_regionkey = r_regionkey
	inner join (
	select
		p_partkey as min_p_partkey,
		min(ps_supplycost) as min_ps_supplycost
	from
		partsupp
		left join part on p_partkey = ps_partkey
		left join supplier on s_suppkey = ps_suppkey
		left join nation on s_nationkey = n_nationkey
		left join region on n_regionkey = r_regionkey
	where
		r_name = 'AMERICA'
	group by
		p_partkey
) on ps_supplycost = min_ps_supplycost and p_partkey = min_p_partkey
where
	p_size = 9
	and p_type like '%COPPER'
	and r_name = 'AMERICA'
order by
	s_acctbal desc,
	n_name,
	s_name,
	p_partkey 
limit 100 
