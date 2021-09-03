-- [origin]

select
	p_brand,
	p_type,
	p_size,
	count(distinct ps_suppkey) as supplier_cnt
from
	partsupp,
	part
where
	p_partkey = ps_partkey
	and p_brand <> 'Brand#15'
	and p_type not like 'ECONOMY BURNISHED%'
	and p_size in (21, 37, 33, 22, 28, 24, 29, 39)
	and ps_suppkey not in (
		select
			s_suppkey
		from
			supplier
		where
			s_comment like '%Customer%Complaints%'
	)
group by
	p_brand,
	p_type,
	p_size
order by
	supplier_cnt desc,
	p_brand,
	p_type,
	p_size 
  

-- [default] change join type  + decorrelate manually


select
	p_brand,
	p_type,
	p_size,
	count(distinct ps_suppkey) as supplier_cnt
from
	partsupp 
	left join part on p_partkey = ps_partkey
	left join supplier on ps_suppkey = s_suppkey
where
	
	p_brand <> 'Brand#15'
	and p_type not like 'ECONOMY BURNISHED%'
	and p_size in (21, 37, 33, 22, 28, 24, 29, 39)
	and 
			s_comment not like '%Customer%Complaints%'
	
group by
	p_brand,
	p_type,
	p_size
order by
	supplier_cnt desc,
	p_brand,
	p_type,
	p_size 