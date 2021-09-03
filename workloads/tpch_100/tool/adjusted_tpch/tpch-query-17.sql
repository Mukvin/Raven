-- [origin]

select
	sum(l_extendedprice) / 7.0 as avg_yearly
from
	lineitem,
	part
where
	p_partkey = l_partkey
	and p_brand = 'Brand#51'
	and p_container = 'MED JAR'
	and l_quantity < (
		select
			0.2 * avg(l_quantity)
		from
			lineitem
		where
			l_partkey = p_partkey
	) 
  
 

-- [default] change join type + decorrelate manually

select sum(l_extendedprice) / 7.0 as avg_yearly
from
    lineitem
    left join part on l_partkey = p_partkey
    inner join (
    select
        l_partkey,
        0.2 * avg(l_quantity) as t_avg_quantity
    from
        lineitem
    group by
        l_partkey
) q17_avg on q17_avg.l_partkey = lineitem.l_partkey
where 
    p_brand = 'Brand#51'
    and p_container = 'MED JAR'
    and l_quantity < t_avg_quantity


